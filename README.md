# Firestack

A userspace TCP/UDP firewall and DNS client for Android.

Firestack is not yet stable and the APIs are still in flux.

Firestack is built specifically for [RethinkDNS](https://github.com/celzero/rethink-app). [go-tun2socks](https://github.com/eycorsican/go-tun2socks) provides
a golang SOCKS-like interface over the tun-device. It does so by wrapping [badvpn's tun2socks](https://github.com/ambrop72/badvpn) in cgo, which in turn
relies on [LwIP](https://www.nongnu.org/lwip/2_1_x/index.html), a light-weight, single-threaded userspace TCP/IP stack underneath the covers.

Firestack is a hard-fork of Google's [outline-go-tun2socks](https://github.com/Jigsaw-Code/outline-go-tun2socks) project.

## Releases

Firestack is released as an Android Library (`aar`) and can be integrated into
your [Android builds via jitpack.io](https://jitpack.io/#celzero/firestack) ([ref](https://github.com/celzero/rethink-app/commit/a6e2abca7)).

```kotlin
    # add this to your project's build.gradle
    allprojects {
        repositories {
            ...
            maven { url 'https://jitpack.io' }
        }
    }

    # add the dep to your app's build.gradle
    dependencies {
        implementation 'com.github.celzero:firestack:Tag'
    }
```

## API

The APIs aren't stable and hence left undocumented, but you can look at
RethinkDNS ([GoVpnAdapter](https://github.com/celzero/rethink-app/blob/982849564/app/src/main/java/com/celzero/bravedns/net/go/GoVpnAdapter.java#L164-L232),
 [BraveVpnService](https://github.com/celzero/rethink-app/blob/982849564/app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt#L130-L137)) to
see how to integrate with Firestack on Android.

## Build

Firestack APIs are available only on Android builds for now. iOS and Linux
support will come by fall 2021.

### Prerequisites

- macOS host and Xcode (iOS, macOS)
- make
- Go >= 1.14
- A C compiler (e.g.: clang, gcc)
- [gomobile](https://github.com/golang/go/wiki/Mobile) (iOS, macOS, Android)
- [xgo](https://github.com/techknowlogick/xgo) (Windows, Linux)
- Docker (Windows, Linux)
- Other common utilities (e.g.: git)

### macOS Framework

As of Go 1.14, `gomobile` does not support building frameworks for macOS. [Jigsaw](https://jigsaw.google.com)
engineers have patched gomobile to enable building a framework for macOS by
replacing the default iOS simulator build. Until the change is upstreamed,
the (Darwin) binary to enable this behavior is located at `tools/gomobile` and
is used by the `build_macos.sh` build script.

### Linux and Windows

Not maintained right now but you can build binaries for Linux and Windows
from source without any custom integrations. `xgo` and Docker are required to
support cross-compilation.

### Build the "Intra" flavour for Android

```bash
go get -d ./...

# the only supported flavour right now
./build_android.sh intra

# other unsupported, unmaintained builds:
./build_[ios|linux|macos|windows].sh
```
