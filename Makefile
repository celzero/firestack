BUILDDIR=$(CURDIR)/build
TOOLSDIR=$(CURDIR)/tools
GOBIN=$(CURDIR)/bin
GOMOBILE=$(GOBIN)/gomobile
GOPATCHOVERLAY=$(GOBIN)/go-patch-overlay
IMPORT_PATH=github.com/celzero/firestack
ELECTRON_PATH=$(IMPORT_PATH)/outline/electron
XGO=$(GOBIN)/xgo
COMMIT_ID=$(shell git rev-parse --short HEAD)
DATESTR=$(shell date -u +'%Y%m%d%H%M%S')
XGO_LDFLAGS='-s -w -X main.version=$(COMMIT_ID)'
# github.com/xjasonlyu/tun2socks/blob/bf745d0e0/Makefile#L14
LDFLAGS_DEBUG='-checklinkname=0 -X $(IMPORT_PATH)/intra/core.Date=$(DATESTR) -X $(IMPORT_PATH)/intra/core.Commit=$(COMMIT_ID)'
# checklinkname to override runtime.secureMode; see: core/runtime/overreach.go
# github.com/golang/go/issues/69868
LDFLAGS='-checklinkname=0 -w -s -buildid= -X $(IMPORT_PATH)/intra/core.Date=$(DATESTR) -X $(IMPORT_PATH)/intra/core.Commit=$(COMMIT_ID)'
# without -s -w so DWARF from C/CGO objects is preserved for llvm-objcopy
# extraction in the debugsymbols target; must come before CGO_LDFLAGS :=
CGO_LDFLAGS_DEBUG:="$(CGO_LDFLAGS) -Wl,-z,max-page-size=16384"
CGO_LDFLAGS:="$(CGO_LDFLAGS) -s -w -Wl,-z,max-page-size=16384"
# build overlay json via recipe
BUILD_OVERLAY=$(BUILDDIR)/overlay.json

# github.com/golang/mobile/blob/a1d90793fc/cmd/gomobile/bind.go#L36
GOBIND=bind -trimpath -v -x -a -javapkg com.celzero.firestack
# -work: keep the temporary directory for debugging
ANDROID23=-androidapi 23 -target=android -tags='android' -work
# -tags debuglog to enable runtime crash logging output with "<< begin log" prefix
# example debug log: github.com/golang/go/issues/69629#issuecomment-2389297820
# build-time tags may be required in somecases
# github.com/golang/go/blob/e2fef50def98/src/runtime/HACKING.md?plain=1#L524
# github.com/golang/go/blob/e2fef50def98/src/runtime/debuglog.go#L63-L64
ANDROID23_DEBUG=-androidapi 23 -target=android -tags='android,debuglog' -work

WINDOWS_BUILDDIR=$(BUILDDIR)/windows
LINUX_BUILDDIR=$(BUILDDIR)/linux

# NDK llvm-objcopy for extracting / stripping debug symbols from .so files
# ANDROID_NDK_HOME is exported by make-aar (or set in the environment)
NDK_ROOT ?= $(ANDROID_NDK_HOME)
# First tries the NDK-canonical path
# falls back to command -v llvm-objcopy from PATH
# Last resort: just llvm-objcopy (so it fails with a clearer error)
LLVM_OBJCOPY ?= $(shell \
  ndkcp="$(NDK_ROOT)/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy"; \
  if [ -x "$$ndkcp" ]; then echo "$$ndkcp"; else command -v llvm-objcopy 2>/dev/null || echo "llvm-objcopy"; fi)
ARCHS = armeabi-v7a arm64-v8a x86 x86_64
DEBUG_SYMBOLS_DIR = $(BUILDDIR)/intra/debug-symbols
DEBUG_SYMBOLS_ZIP = $(BUILDDIR)/intra/tun2socks-debug-symbols.zip
DEBUG_UNSTRIPPED_DIR = $(BUILDDIR)/intra/unstripped

# stack traces are not affected by ldflags -s -w: github.com/golang/go/issues/25035#issuecomment-495004689
# trimpath: github.com/skycoin/skycoin/issues/719
# GOTOOLCHAIN=local: force use of the locally installed toolchain so that runtime
# sources live under GOROOT (overlayable), not GOMODCACHE (not overlayable).
# ref: https://github.com/golang/go/issues/44129
ANDROID_BUILD_CMD=env GOTOOLCHAIN=local GODEBUG=cgocheck=0 PATH=$(GOBIN):$(PATH) $(GOMOBILE) $(GOBIND) $(ANDROID23) \
				-overlay=$(BUILD_OVERLAY) -ldflags $(LDFLAGS) -gcflags='-trimpath'
# built without stripping dwarf/symbols
ANDROID_DEBUG_BUILD_CMD=env GOTOOLCHAIN=local GODEBUG=cgocheck=0 PATH=$(GOBIN):$(PATH) CGO_LDFLAGS=$(CGO_LDFLAGS_DEBUG) $(GOMOBILE) $(GOBIND) $(ANDROID23_DEBUG) \
				-overlay=$(BUILD_OVERLAY) -ldflags $(LDFLAGS_DEBUG)
# exported pkgs
INTRA_BUILD_CMD=$(IMPORT_PATH)/intra $(IMPORT_PATH)/intra/backend $(IMPORT_PATH)/intra/settings

$(BUILDDIR)/intra/tun2socks.aar: $(GOMOBILE) $(BUILD_OVERLAY)
	mkdir -p $(BUILDDIR)/intra
	$(ANDROID_BUILD_CMD) -o $@ $(INTRA_BUILD_CMD)

$(BUILDDIR)/intra/tun2socks-debug.aar: $(GOMOBILE) $(BUILD_OVERLAY)
	mkdir -p $(BUILDDIR)/intra
	$(ANDROID_DEBUG_BUILD_CMD) -o $@ $(INTRA_BUILD_CMD)

$(BUILDDIR)/android/tun2socks.aar: $(GOMOBILE) $(BUILD_OVERLAY)
	env NDK_DEBUG=0
	mkdir -p $(BUILDDIR)/android
	$(ANDROID_BUILD_CMD) -o $@ $(IMPORT_PATH)/outline/android $(IMPORT_PATH)/outline/shadowsocks

$(BUILD_OVERLAY): $(TOOLSDIR)/runtime_write_err_android.patch
	mkdir -p $(BUILDDIR)
	env PATH=$(GOBIN):$(PATH) $(GOPATCHOVERLAY) -overlay $(BUILDDIR) $(TOOLSDIR)/runtime_write_err_android.patch

$(LINUX_BUILDDIR)/tun2socks: $(XGO)
	$(XGO) -ldflags $(XGO_LDFLAGS) --targets=linux/amd64 -dest $(LINUX_BUILDDIR) $(ELECTRON_PATH)
	mv $(LINUX_BUILDDIR)/electron-linux-amd64 $@

$(WINDOWS_BUILDDIR)/tun2socks.exe: $(XGO)
	$(XGO) -ldflags $(XGO_LDFLAGS) --targets=windows/386 -dest $(WINDOWS_BUILDDIR) $(ELECTRON_PATH)
	mv $(WINDOWS_BUILDDIR)/electron-windows-4.0-386.exe $@

# MACOSX_DEPLOYMENT_TARGET and -iosversion should match what outline-client supports.
$(BUILDDIR)/apple/Tun2socks.xcframework: $(GOMOBILE)
	export MACOSX_DEPLOYMENT_TARGET=10.14; $(GOMOBILE) $(GOBIND) -iosversion=9.0 -target=ios,iossimulator,macos -o $@ -ldflags '-s -w' -bundleid org.outline.tun2socks $(IMPORT_PATH)/outline/apple $(IMPORT_PATH)/outline/shadowsocks

go.mod: tools/tools.go
	go mod tidy
	touch go.mod

$(GOMOBILE): go.mod
	env GOBIN=$(GOBIN) go install golang.org/x/mobile/cmd/gomobile@latest
	env GOBIN=$(GOBIN) go install github.com/felixge/go-patch-overlay@latest
	env PATH=$(GOBIN):$(PATH) $(GOMOBILE) init

$(XGO): go.mod
	env GOBIN=$(GOBIN) go install github.com/crazy-max/xgo

# Extract per-arch debug symbols from the unstripped debug AAR, then strip the
# .so files in-place and repack the AAR. The resulting AAR is stripped (smaller
# for distribution) and the symbol files are bundled into a separate zip.
# ref: github.com/tailscale/tailscale-android/commit/24d737834a1ff57eaa1daeb52708c918c7cd2e48
$(DEBUG_SYMBOLS_ZIP): $(BUILDDIR)/intra/tun2socks-debug.aar
	mkdir -p $(DEBUG_SYMBOLS_DIR)
	mkdir -p $(DEBUG_UNSTRIPPED_DIR)
	@set -e; \
	tmpdir=$$(mktemp -d); \
	trap "rm -rf $$tmpdir" EXIT; \
	unzip -q $< -d $$tmpdir; \
	for arch in $(ARCHS); do \
		so=$$tmpdir/jni/$$arch/libgojni.so; \
		[ -f $$so ] || continue; \
		mkdir -p $(DEBUG_SYMBOLS_DIR)/jni/$$arch; \
		mkdir -p $(DEBUG_UNSTRIPPED_DIR)/jni/$$arch; \
		cp $$so $(DEBUG_UNSTRIPPED_DIR)/jni/$$arch/libgojni.so; \
		echo "cp unstripped $$arch/libgojni.so => $(DEBUG_UNSTRIPPED_DIR)/jni/$$arch/libgojni.so"; \
		$(LLVM_OBJCOPY) --only-keep-debug $$so $(DEBUG_SYMBOLS_DIR)/jni/$$arch/libgojni.so; \
		$(LLVM_OBJCOPY) --strip-debug --strip-unneeded $$so; \
		echo "stripped $$arch/libgojni.so, debug-only => $(DEBUG_SYMBOLS_DIR)/jni/$$arch/libgojni.so"; \
	done; \
	ls -Rltr $$tmpdir; \
	stripped=$<.stripped; (cd $$tmpdir && zip -qr "$$stripped" .) && mv "$$stripped" $<; \
	(cd $(DEBUG_SYMBOLS_DIR) && zip -qr $@ jni/) \
	&& echo "created debug symbols zip: $@" \
	ls -Rltr ${DEBUG_SYMBOLS_DIR}

.PHONY: android intra linux apple windows debugsymbols clean clean-all

all: android intra linux apple windows

android: $(BUILDDIR)/android/tun2socks.aar

intra: $(BUILDDIR)/intra/tun2socks.aar

intradebug: $(BUILDDIR)/intra/tun2socks-debug.aar debugsymbols

debugsymbols: $(DEBUG_SYMBOLS_ZIP)

apple: $(BUILDDIR)/apple/Tun2socks.xcframework

linux: $(LINUX_BUILDDIR)/tun2socks

windows: $(WINDOWS_BUILDDIR)/tun2socks.exe

clean:
	rm -rf $(BUILDDIR)
	go clean

clean-all: clean
	rm -rf $(GOBIN)
