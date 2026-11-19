#!/usr/bin/env bash
set -euo pipefail

# Inputs are the already verified matrix artifacts, not files from public feeds.
[[ $# == 3 && $3 =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo 'Usage: pages-repositories.sh MATRIX_DIR SITE_DIR vX.Y.Z' >&2; exit 2;
}
packages=$(realpath "$1")
site=$(realpath "$2")
tag=$3
: "${PAGES_GPG_FINGERPRINT:?}" "${ALPINE_SIGNING_KEY:?}" "${OPENWRT_SIGNING_KEY:?}"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
umask 077
cp "$ALPINE_SIGNING_KEY" "$work/alpine.rsa"
cp "$OPENWRT_SIGNING_KEY" "$work/openwrt.pem"
umask 022
mkdir -p "$site/keys" "$site/portable"
mkdir "$site/portable/$tag"
# Keep previously published trust roots immutable until an explicit rotation.
public_key() {
    local name=$1
    if [[ -e $site/keys/$name ]]; then
        cmp "$work/trusted/$name" "$site/keys/$name"
    else
        install -m644 "$work/trusted/$name" "$site/keys/$name"
    fi
}
mkdir "$work/trusted"
openssl pkey -in "$work/alpine.rsa" -pubout -out "$work/trusted/cat4igp-alpine.rsa.pub"
openssl pkey -in "$work/openwrt.pem" -pubout -out "$work/trusted/cat4igp-openwrt.pem.pub"
gpg --batch --armor --export "$PAGES_GPG_FINGERPRINT" > "$work/trusted/cat4igp.asc"
test -s "$work/trusted/cat4igp.asc"
for key in cat4igp.asc cat4igp-alpine.rsa.pub cat4igp-openwrt.pem.pub; do public_key "$key"; done
sign=(gpg --batch --yes --local-user "$PAGES_GPG_FINGERPRINT")

shopt -s nullglob
artifact() {
    local target=$1 extension=$2
    local files=("$packages/client-$target/"cat4igp-client-*"$extension")
    # Debian filenames start with an underscore after the package name.
    if [[ $extension == .deb ]]; then files=("$packages/client-$target/"cat4igp-client_*.deb); fi
    [[ ${#files[@]} == 1 && -f ${files[0]} ]] || { echo "Expected one artifact for $target" >&2; exit 1; }
    input=${files[0]}
}
copy_package() {
    mkdir -p "$1"
    output=$1/${input##*/}
    [[ ! -e $output ]] || { echo "Package already exists: $output" >&2; exit 1; }
    install -m644 "$input" "$output"
}

for arch in x86_64 aarch64 riscv64; do
    case $arch in x86_64) debarch=amd64;; aarch64) debarch=arm64;; *) debarch=$arch;; esac
    artifact "debian-$arch" .deb
    test "$(dpkg-deb -f "$input" Architecture)" = "$debarch"
    copy_package "$site/debian/pool/$debarch"
    dir="dists/trixie/main/binary-$debarch"
    (
        cd "$site/debian"
        mkdir -p "$dir"
        apt-ftparchive packages "pool/$debarch" > "$dir/Packages"
        gzip -n -c "$dir/Packages" > "$dir/Packages.gz"
    )
done
(
    cd "$site/debian"
    rm -f dists/trixie/{Release,Release.gpg,InRelease}
    apt-ftparchive -o APT::FTPArchive::Release::Origin=CAT4IGP \
        -o APT::FTPArchive::Release::Suite=trixie -o APT::FTPArchive::Release::Codename=trixie \
        -o 'APT::FTPArchive::Release::Architectures=amd64 arm64 riscv64' \
        -o APT::FTPArchive::Release::Components=main release dists/trixie > "$work/Release"
    install -m644 "$work/Release" dists/trixie/Release
    "${sign[@]}" --clearsign --output dists/trixie/InRelease dists/trixie/Release
)

# Resolve tools before mounting signing keys; signing containers have no network.
alpine_tools=$(docker build -q - <<'EOF'
FROM alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk add --no-cache abuild
EOF
)

for arch in x86_64 aarch64 riscv64; do
    artifact "alpine-$arch" .apk
    copy_package "$site/alpine/v3.24/$arch"
    docker run --rm --network none -v "${output%/*}:/feed" -v "$work:/keys:ro" \
        -e "PACKAGE=${output##*/}" -e "OWNER=$(id -u):$(id -g)" "$alpine_tools" sh -ec '
        cd "$(mktemp -d)"
        abuild-gzsplit < "/feed/$PACKAGE"
        test -s control.tar.gz && test -s data.tar.gz
        abuild-sign -k /keys/alpine.rsa -p /keys/trusted/cat4igp-alpine.rsa.pub control.tar.gz
        cat control.tar.gz data.tar.gz > "/feed/$PACKAGE"
        cd /feed
        apk index --keys-dir /keys/trusted -o APKINDEX.tar.gz ./*.apk
        abuild-sign -k /keys/alpine.rsa -p /keys/trusted/cat4igp-alpine.rsa.pub APKINDEX.tar.gz
        chown "$OWNER" APKINDEX.tar.gz
    '
done

for arch in x86_64 aarch64; do
    apkarch=$arch
    [[ $arch != aarch64 ]] || apkarch=aarch64_generic
    artifact "openwrt-$arch" .apk
    copy_package "$site/openwrt/25.12.5/$apkarch"
    docker run --rm --network none --user "$(id -u):$(id -g)" -v "${output%/*}:/feed" -v "$work:/keys:ro" -w /feed -e "PACKAGE=${output##*/}" \
        alpine@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf sh -ec '
        apk adbsign --allow-untrusted --reset-signatures --sign-key /keys/openwrt.pem "$PACKAGE"
        apk mkndx --keys-dir /keys/trusted --sign-key /keys/openwrt.pem --output packages.adb ./*.apk
    '
done

artifact arch-x86_64 .pkg.tar.zst
copy_package "$site/arch/x86_64"
"${sign[@]}" --detach-sign "$output"
(
    cd "$site/arch/x86_64"
    rm -f cat4igp.{db,files}*
    # Pages does not serve repository database symlinks. Publish regular files.
    docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/feed" -w /feed \
        archlinux@sha256:b21322c663be387c0ed9cbc7bbbfe18e41633ad4e7b7c77cfad45f128be20040 \
        bash -ec 'repo-add --prevent-downgrade --include-sigs cat4igp.db.tar.gz ./*.pkg.tar.zst'
    for name in cat4igp.db cat4igp.files; do
        rm "$name"
        cp "$name.tar.gz" "$name"
        "${sign[@]}" --detach-sign "$name"
    done
)

for arch in x86_64 aarch64; do
    artifact "static-$arch" -unknown-linux-musl
    copy_package "$site/portable/$tag"
done
(
    cd "$site/portable/$tag"
    sha256sum cat4igp-client-* > SHA256SUMS
    "${sign[@]}" --armor --detach-sign SHA256SUMS
    gpg --batch --verify SHA256SUMS.asc SHA256SUMS
    sha256sum --check SHA256SUMS
)
chmod -R a+rX "$site/debian" "$site/alpine" "$site/openwrt" "$site/arch" "$site/portable"
touch "$site/.nojekyll"
