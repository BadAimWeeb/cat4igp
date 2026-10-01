include $(TOPDIR)/rules.mk

PKG_NAME:=cat4igp-client
PKG_VERSION?=0.1.0
PKG_RELEASE:=1

# Local full-workspace archive, staged in the SDK's dl directory.
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=file://$(DL_DIR)
# ponytail: local workflow sources only; pass PKG_HASH for verified release archives.
PKG_HASH?=skip
PKG_LICENSE:=MIT
# Workflow installs pinned upstream rustc/cargo and the target standard library.
# ponytail: x86_64/aarch64 musl only; restore rust/host for custom Rust targets.
PKG_BUILD_DEPENDS:=cmake/host
PKG_BUILD_PARALLEL:=1
MAKE_PATH:=client

include $(INCLUDE_DIR)/package.mk
include $(TOPDIR)/feeds/packages/lang/rust/rust-package.mk

define Package/cat4igp-client
  SECTION:=net
  CATEGORY:=Network
  TITLE:=WireGuard mesh network client
  URL:=https://github.com/BadAimWeeb/cat4igp
  DEPENDS:=$(RUST_ARCH_DEPENDS) +ca-bundle +kmod-wireguard +libgcc
endef

define Package/cat4igp-client/conffiles
/etc/cat4igp/client.toml
endef

define Build/Compile
	sh -n ./files/cat4igp-client.init
	sh -ec 'pkgname=cat4igp-client; action=enable; . ./files/cat4igp-client.init; enable; ! type start_service >/dev/null 2>&1'
	sh -ec 'pkgname=cat4igp-client; action=start; . ./files/cat4igp-client.init; start; ! type start_service >/dev/null 2>&1'
	sh -ec 'unset pkgname; . ./files/cat4igp-client.init; type start_service >/dev/null'
	$(call Build/Compile/Cargo,,--bin cat4igp-client)
	test -x $(PKG_INSTALL_DIR)/bin/cat4igp-client
endef

define Package/cat4igp-client/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/cat4igp
	$(INSTALL_BIN) $(PKG_INSTALL_DIR)/bin/cat4igp-client $(1)/usr/bin/
	$(INSTALL_BIN) ./files/cat4igp-client.init $(1)/etc/init.d/cat4igp-client
	$(INSTALL_CONF) ./files/client.toml $(1)/etc/cat4igp/client.toml
	chmod 0600 $(1)/etc/cat4igp/client.toml
	$(INSTALL_DIR) $(1)/etc/cat4igp/state
	chmod 0700 $(1)/etc/cat4igp/state
	$(INSTALL_DIR) $(1)/usr/share/licenses/cat4igp-client
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/LICENSE $(1)/usr/share/licenses/cat4igp-client/LICENSE
	$(INSTALL_DIR) $(1)/lib/upgrade/keep.d
	printf '%s\n' '/etc/cat4igp/client.toml' '/etc/cat4igp/state/' > $(1)/lib/upgrade/keep.d/cat4igp-client
endef

$(eval $(call BuildPackage,cat4igp-client))