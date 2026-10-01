#!/usr/bin/env bash
set -euo pipefail

die() { echo "$*" >&2; exit 1; }
root=${CAT4IGP_SOURCE_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$root/client/Cargo.toml" | head -n1)
[[ $version =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || die 'Client version must be X.Y.Z'

pkgversion() {
    local distro=$1 ref=$2 stamp=$3 sha=$4
    [[ $stamp =~ ^[0-9]{14}$ && $sha =~ ^[0-9a-f]{40}$ ]] || return 1
    case $distro in alpine|debian|arch|openwrt|static) ;; *) return 1 ;; esac
    if [[ $ref == refs/tags/* ]]; then
        [[ $ref == "refs/tags/v$version" ]] || return 1
        printf '%s\n' "$version"
    else
        case $distro in
            # Alpine suffixes accept numbers, not arbitrary hexadecimal hashes.
            alpine|openwrt) printf '%s_alpha%s_git%d\n' "$version" "$stamp" "$((16#${sha:0:12}))" ;;
            arch) printf '%salpha%s.g%s\n' "$version" "$stamp" "${sha:0:12}" ;;
            *) printf '%s~%s.g%s\n' "$version" "$stamp" "${sha:0:12}" ;;
        esac
    fi
}

if [[ ${1:-} == --check ]]; then
    [[ $# == 1 ]] || die 'Usage: build.sh --check'
    sha=0123456789abcdef0123456789abcdef01234567
    for distro in alpine debian arch openwrt static; do
        [[ $(pkgversion "$distro" "refs/tags/v$version" 20261001000000 "$sha") == "$version" ]]
        pkgversion "$distro" refs/heads/main 20261001000000 "$sha" >/dev/null
        if pkgversion "$distro" refs/tags/v999.0.0 20261001000000 "$sha"; then die 'Accepted mismatched tag'; fi
    done
    [[ $(pkgversion alpine main 20261001000000 "$sha") == "${version}_alpha20261001000000_git1250999896491" ]]
    [[ $(pkgversion openwrt main 20261001000000 "$sha") == "${version}_alpha20261001000000_git1250999896491" ]]
    [[ $(pkgversion arch main 20261001000000 "$sha") == "${version}alpha20261001000000.g0123456789ab" ]]
    [[ $(pkgversion debian main 20261001000000 "$sha") == "${version}~20261001000000.g0123456789ab" ]]
    if [[ ${GITHUB_REF:-} == refs/tags/* ]]; then
        pkgversion debian "$GITHUB_REF" 20261001000000 "$sha" >/dev/null || die 'Tag does not match client/Cargo.toml'
    fi
    if pkgversion bogus main invalid invalid; then die 'Accepted invalid input'; fi
    echo 'Version/input checks passed'
    exit
fi

[[ $# == 2 || ($# == 3 && $3 == --inside) ]] || die 'Usage: build.sh DISTRO ARCH | --check'
distro=$1 arch=$2
case "$distro/$arch" in alpine/x86_64|alpine/aarch64|debian/x86_64|debian/aarch64|arch/x86_64|openwrt/x86_64|openwrt/aarch64|static/x86_64|static/aarch64) ;; *) die 'Unsupported target' ;; esac
expected_host=$arch
[[ $distro != openwrt ]] || expected_host=x86_64
[[ $(uname -m) == "$expected_host" ]] || die "This build requires a $expected_host host"
ref=${GITHUB_REF:-refs/heads/local}
sha=${GITHUB_SHA:-$(git -C "$root" rev-parse HEAD)}
stamp=$(git -C "$root" show -s --format=%cI "$sha")
stamp=$(date -u -d "$stamp" +%Y%m%d%H%M%S)
pkgver=$(pkgversion "$distro" "$ref" "$stamp" "$sha") || die 'Invalid version inputs or tag does not match client/Cargo.toml'
export CAT4IGP_PKGVER=$pkgver

if [[ ${3:-} != --inside ]]; then
    case "$distro/$arch" in
        alpine/*|static/*) image=alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 ;;
        debian/*|openwrt/*) image=debian@sha256:9cc080028c43b27d2074d63a5f9caf7166d731494965616c1a6d2827a004585c ;;
        arch/x86_64) image=archlinux@sha256:b21322c663be387c0ed9cbc7bbbfe18e41633ad4e7b7c77cfad45f128be20040 ;;
    esac
    mkdir -p "$root/dist/$distro-$arch"
    # Native runners only; both OpenWrt SDKs execute on x86_64.
    docker run --rm -v "$root:/repo:ro" -v "$root/dist/$distro-$arch:/out" \
        -e GITHUB_REF="$ref" -e GITHUB_SHA="$sha" -e OUTPUT_UID="$(id -u)" -e OUTPUT_GID="$(id -g)" \
        "$image" sh -ec '
            case "$1" in
                alpine|static) apk add --no-cache bash git coreutils ;;
                debian|openwrt) apt-get update; apt-get install -y --no-install-recommends bash git ca-certificates ;;
                arch) pacman-key --init; pacman-key --populate; pacman -Syu --noconfirm bash git ;;
            esac
            git config --system --add safe.directory /repo
            # Keep the executing script stable if the checkout is edited during a build.
            cp /repo/packaging/build.sh /tmp/cat4igp-build.sh
            CAT4IGP_SOURCE_ROOT=/repo exec bash /tmp/cat4igp-build.sh "$1" "$2" --inside
        ' sh "$distro" "$arch"
    exit
fi

[[ $(id -u) == 0 ]] || die 'Container bootstrap requires root'
case $distro in
    alpine|static)
        apk add --no-cache alpine-sdk cmake curl musl-dev gcc g++ libgcc coreutils perl linux-headers
        adduser -D builder; addgroup builder abuild ;;
    debian|openwrt)
        apt-get install -y --no-install-recommends build-essential cmake curl debhelper devscripts fakeroot \
            python3 python3-setuptools unzip file rsync gawk gettext libncurses-dev zstd wget perl patch \
            bzip2 flex bison libssl-dev libelf-dev time
        useradd -m builder ;;
    arch)
        pacman -S --needed --noconfirm base-devel cmake curl
        useradd -m builder ;;
esac
work=$(mktemp -d /tmp/cat4igp.XXXXXX)
trap 'rm -rf "$work"' EXIT
mkdir "$work/workspace"
tar -C "$root" --exclude=.git --exclude=target --exclude=dist -cf - . | tar -C "$work/workspace" -xf -
for file in Cargo.lock LICENSE packaging/client.toml packaging/cat4igp-client.service packaging/cat4igp-client.openrc; do
    [[ -f $work/workspace/$file ]] || die "Missing shared input: $file"
done
chown -R builder:builder "$work"
chmod 755 "$work"
export WORK=$work DISTRO=$distro ARCH=$arch
if [[ $distro == alpine ]]; then
    su builder -s /bin/sh -c 'abuild-keygen -n -a'
    cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/
fi
# ponytail: standalone unsigned packages, no signed repositories; add repository metadata/signing when hosting repositories.
su builder -s /bin/bash <<'BUILD'
set -euo pipefail
cd "$WORK"
export PATH="$HOME/.cargo/bin:$PATH"
if [[ $DISTRO != openwrt ]]; then
    host="$ARCH-unknown-linux-gnu"
    [[ $DISTRO != alpine && $DISTRO != static ]] || host="$ARCH-unknown-linux-musl"
    curl -fL --retry 3 https://sh.rustup.rs -o rustup.sh
    sh rustup.sh -y --profile minimal --default-host "$host" --default-toolchain 1.94.0
    export RUSTUP_TOOLCHAIN=1.94.0
fi
case $DISTRO in
    static)
        cd workspace
        target="$ARCH-unknown-linux-musl"
        case $ARCH in
            x86_64) cpu=x86-64; machine='Advanced Micro Devices X86-64' ;;
            aarch64) cpu=generic; machine=AArch64 ;;
        esac
        export RUSTFLAGS="-C target-cpu=$cpu -C target-feature=+crt-static"
        case $ARCH in
            x86_64) export CFLAGS='-O2 -march=x86-64' ;;
            aarch64) export CFLAGS='-O2 -march=armv8-a' ;;
        esac
        export CXXFLAGS="$CFLAGS"
        cargo build --locked --release -p cat4igp-client --target "$target"
        binary="target/$target/release/cat4igp-client"
        strip "$binary"
        # Native ELF checks reject accidental loader/shared-library dependencies.
        readelf -h "$binary" | grep -F "$machine"
        ! readelf -l "$binary" | grep -q INTERP
        ! readelf -d "$binary" | grep -q NEEDED
        "$binary" --help >/dev/null
        install -m755 "$binary" "$WORK/cat4igp-client-$CAT4IGP_PKGVER-$target" ;;
    alpine)
        cp workspace/packaging/alpine/APKBUILD .
        # Dependencies installed above; no privileged dependency installation by the builder.
        pkgver="$CAT4IGP_PKGVER" abuild -d
        find "$HOME/packages" -name 'cat4igp-client-*.apk' -exec cp {} "$WORK/" \; ;;
    debian)
        cp -a workspace/packaging/debian workspace/debian
        cd workspace
        chmod +x debian/rules
        DEBFULLNAME=BadAimWeeb DEBEMAIL=badaimweeb@protonmail.com \
            dch --force-bad-version --newversion "$CAT4IGP_PKGVER-1" --distribution trixie 'CI client build.'
        dpkg-buildpackage -b -us -uc ;;
    arch)
        cp workspace/packaging/arch/PKGBUILD .
        makepkg --noconfirm ;;
    openwrt)
        case $ARCH in
            x86_64) target=x86/64; name=x86-64; checksum=0c8df0151a1e88feb7c03d694d61f6a18d51872815b7c811d76e2b77504d5e9c ;;
            aarch64) target=armsr/armv8; name=armsr-armv8; checksum=1b0316604a3e820b2b008a1baff3f9dac6716af942bef800930e58c7de98c98b ;;
        esac
        sdk="openwrt-sdk-25.12.5-${name}_gcc-14.3.0_musl.Linux-x86_64"
        curl -fL --retry 3 "https://downloads.openwrt.org/releases/25.12.5/targets/$target/$sdk.tar.zst" -o sdk.tar.zst
        printf '%s  sdk.tar.zst\n' "$checksum" | sha256sum -c -
        tar --zstd -xf sdk.tar.zst
        cd "$sdk"
        printf '%s\n' 'src-git packages https://git.openwrt.org/feed/packages.git^5caa62e0bc9f7fb9b0c12a23267bceb7724214dd' > feeds.conf
        ./scripts/feeds update packages
        [[ $(git -C feeds/packages rev-parse HEAD) == 5caa62e0bc9f7fb9b0c12a23267bceb7724214dd ]]
        ./scripts/feeds install rust
        cp -a "$WORK/workspace/packaging/openwrt" package/cat4igp-client
        mkdir -p dl
        archive="cat4igp-client-$CAT4IGP_PKGVER"
        tar -C "$WORK" --transform="s,^workspace,$archive," -czf "dl/$archive.tar.gz" workspace
        hash=$(sha256sum "dl/$archive.tar.gz" | cut -d' ' -f1)
        # Scope overrides to our staged recipe, not rust/host or other SDK dependencies.
        sed -i "s/^PKG_VERSION?=.*/PKG_VERSION:=$CAT4IGP_PKGVER/; s/^PKG_HASH?=.*/PKG_HASH:=$hash/" package/cat4igp-client/Makefile
        printf '%s\n' 'CONFIG_PACKAGE_cat4igp-client=y' > .config
        make defconfig
        make -j"$(nproc)" package/cat4igp-client/compile V=s
        find bin/packages -name 'cat4igp-client-*.apk' -exec cp {} "$WORK/" \; ;;
esac
BUILD
mapfile -t packages < <(find "$work" -maxdepth 1 -type f \( -name '*.apk' -o -name '*.deb' -o -name '*.pkg.tar.zst' -o -name 'cat4igp-client-*-unknown-linux-musl' \))
[[ ${#packages[@]} == 1 ]] || die "Expected one client package, found ${#packages[@]}"
mode=644
[[ $distro != static ]] || mode=755
install -m"$mode" "${packages[0]}" /out/
chown "$OUTPUT_UID:$OUTPUT_GID" "/out/$(basename "${packages[0]}")"