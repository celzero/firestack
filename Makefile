BUILDDIR=$(CURDIR)/build
GOBIN=$(CURDIR)/bin
GOMOBILE=$(GOBIN)/gomobile
ELECTRON_PATH=$(IMPORT_PATH)/outline/electron
XGO=$(GOBIN)/xgo
IMPORT_PATH=github.com/celzero/firestack
COMMIT_ID=$(git rev-parse --short HEAD)
XGO_LDFLAGS='-s -w -X main.version=$(COMMIT_ID)'

WINDOWS_BUILDDIR=$(BUILDDIR)/windows
LINUX_BUILDDIR=$(BUILDDIR)/linux

# stack traces are not affected by ldflags -s -w: github.com/golang/go/issues/25035#issuecomment-495004689
ANDROID_BUILD_CMD=env PATH=$(GOBIN):$(PATH) $(GOMOBILE) bind -v -a -ldflags '-w -s' -androidapi 23 -target=android -tags='android' -work
# built without stripping dwarf/symbols
ANDROID_ARM64_BUILD_CMD=env PATH=$(GOBIN):$(PATH) $(GOMOBILE) bind -v -a -androidapi 23 -target=android/arm64 -tags='android' -work
# exported pkgs
INTRA_BUILD_CMD=$(IMPORT_PATH)/intra $(IMPORT_PATH)/intra/backend $(IMPORT_PATH)/intra/rnet $(IMPORT_PATH)/intra/settings

$(BUILDDIR)/intra/tun2socks.aar: $(GOMOBILE)
	mkdir -p $(BUILDDIR)/intra
	$(ANDROID_BUILD_CMD) -o $@ $(INTRA_BUILD_CMD)

$(BUILDDIR)/intra/tun2socks-arm.aar: $(GOMOBILE)
	mkdir -p $(BUILDDIR)/intra
	$(ANDROID_ARM64_BUILD_CMD) -o $@ $(INTRA_BUILD_CMD)

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

intrarm: $(BUILDDIR)/intra/tun2socks-arm.aar

apple: $(BUILDDIR)/apple/Tun2socks.xcframework

linux: $(LINUX_BUILDDIR)/tun2socks

windows: $(WINDOWS_BUILDDIR)/tun2socks.exe

clean:
	rm -rf $(BUILDDIR)
	go clean

clean-all: clean
	rm -rf $(GOBIN)
