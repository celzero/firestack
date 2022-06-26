BUILDDIR=$(CURDIR)/build
GOBIN=$(CURDIR)/bin
GOMOBILE=$(GOBIN)/gomobile
ELECTRON_PATH=$(IMPORT_PATH)/outline/electron
XGO=$(GOBIN)/xgo
IMPORT_PATH=github.com/celzero/firestack
TUN2SOCKS_VERSION=v1.16.11
XGO_LDFLAGS='-s -w -X main.version=$(TUN2SOCKS_VERSION)'

WINDOWS_BUILDDIR=$(BUILDDIR)/windows
LINUX_BUILDDIR=$(BUILDDIR)/linux

ANDROID_BUILD_CMD=env PATH=$(GOBIN):$(PATH) $(GOMOBILE) bind -v -a -trimpath -ldflags '-w' -target=android -tags='android,disable_debug'

$(BUILDDIR)/intra/tun2socks.aar: $(GOMOBILE)
	mkdir -p $(BUILDDIR)/intra
	$(ANDROID_BUILD_CMD) -o $@ $(IMPORT_PATH)/intra $(IMPORT_PATH)/intra/android $(IMPORT_PATH)/intra/ipn $(IMPORT_PATH)/intra/doh $(IMPORT_PATH)/intra/dns53 $(IMPORT_PATH)/intra/split $(IMPORT_PATH)/intra/protect $(IMPORT_PATH)/intra/settings $(IMPORT_PATH)/intra/dnscrypt $(IMPORT_PATH)/intra/dnsx $(IMPORT_PATH)/intra/xdns

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
	export MACOSX_DEPLOYMENT_TARGET=10.14; $(GOMOBILE) bind -iosversion=9.0 -target=ios,iossimulator,macos -o $@ -ldflags '-s -w' -bundleid org.outline.tun2socks $(IMPORT_PATH)/outline/apple $(IMPORT_PATH)/outline/shadowsocks

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

apple: $(BUILDDIR)/apple/Tun2socks.xcframework

linux: $(LINUX_BUILDDIR)/tun2socks

windows: $(WINDOWS_BUILDDIR)/tun2socks.exe

clean:
	rm -rf $(BUILDDIR)
	go clean

clean-all: clean
	rm -rf $(GOBIN)
