BUILDDIR=$(CURDIR)/build
GOBIN=$(CURDIR)/bin
GOMOBILE=$(GOBIN)/gomobile
IMPORT_PATH=github.com/celzero/firestack
ELECTRON_PATH=$(IMPORT_PATH)/outline/electron
XGO=$(GOBIN)/xgo
COMMIT_ID=$(shell git rev-parse --short HEAD)
DATESTR=$(shell date -u +'%Y%m%d%H%M%S')
XGO_LDFLAGS='-s -w -X main.version=$(COMMIT_ID)'
# github.com/xjasonlyu/tun2socks/blob/bf745d0e0/Makefile#L14
LDFLAGS='-w -s -X $(IMPORT_PATH)/intra/core.Date=$(DATESTR) -X $(IMPORT_PATH)/intra/core.Commit=$(COMMIT_ID)'

GOBIND=bind -v -a
# -work: keep the temporary directory for debugging
ANDROID23=-androidapi 23 -target=android -tags='android' -work

WINDOWS_BUILDDIR=$(BUILDDIR)/windows
LINUX_BUILDDIR=$(BUILDDIR)/linux

# stack traces are not affected by ldflags -s -w: github.com/golang/go/issues/25035#issuecomment-495004689
# trimpath: github.com/skycoin/skycoin/issues/719
ANDROID_BUILD_CMD=env PATH=$(GOBIN):$(PATH) $(GOMOBILE) $(GOBIND) $(ANDROID23) \
				-ldflags $(LDFLAGS) -gcflags='-trimpath=${HOME}'
# built without stripping dwarf/symbols
ANDROID_DEBUG_BUILD_CMD=env PATH=$(GOBIN):$(PATH) $(GOMOBILE) $(GOBIND) $(ANDROID23)
# exported pkgs
INTRA_BUILD_CMD=$(IMPORT_PATH)/intra $(IMPORT_PATH)/intra/backend $(IMPORT_PATH)/intra/rnet $(IMPORT_PATH)/intra/settings

$(BUILDDIR)/intra/tun2socks.aar: $(GOMOBILE)
	mkdir -p $(BUILDDIR)/intra
	$(ANDROID_BUILD_CMD) -o $@ $(INTRA_BUILD_CMD)

$(BUILDDIR)/intra/tun2socks-debug.aar: $(GOMOBILE)
	mkdir -p $(BUILDDIR)/intra
	$(ANDROID_DEBUG_BUILD_CMD) -o $@ $(INTRA_BUILD_CMD)

$(BUILDDIR)/android/tun2socks.aar: $(GOMOBILE)
	mkdir -p $(BUILDDIR)/android
	$(ANDROID_BUILD_CMD) -o $@ $(IMPORT_PATH)/outline/android $(IMPORT_PATH)/outline/shadowsocks

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
	env GOBIN=$(GOBIN) go install golang.org/x/mobile/cmd/gomobile
	env PATH=$(GOBIN):$(PATH) $(GOMOBILE) init

$(XGO): go.mod
	env GOBIN=$(GOBIN) go install github.com/crazy-max/xgo

.PHONY: android intra linux apple windows clean clean-all

all: android intra linux apple windows

android: $(BUILDDIR)/android/tun2socks.aar

intra: $(BUILDDIR)/intra/tun2socks.aar

intradebug: $(BUILDDIR)/intra/tun2socks-debug.aar

apple: $(BUILDDIR)/apple/Tun2socks.xcframework

linux: $(LINUX_BUILDDIR)/tun2socks

windows: $(WINDOWS_BUILDDIR)/tun2socks.exe

clean:
	rm -rf $(BUILDDIR)
	go clean

clean-all: clean
	rm -rf $(GOBIN)
