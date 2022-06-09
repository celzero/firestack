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

### Prerequisites

- macOS host (iOS, macOS)
- make
- Go >= 1.18
- A C compiler (e.g.: clang, gcc)

Firestack APIs are available only on Android builds for now. iOS and Linux
support will come by fall 2022.

### Android

- [sdkmanager](https://developer.android.com/studio/command-line/sdkmanager)
  1. Download the command line tools from [developer.android.com](https://developer.android.com/studio).
  1. Unzip the pacakge as `~/Android/Sdk/cmdline-tools/latest/`. Make sure `sdkmanager` is located at `~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager`
- Android NDK 23+
  1. Install the NDK with `~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager "platforms;android-30" "ndk;23.1.7779620"`
    (platform from [outline-client](https://github.com/Jigsaw-Code/outline-client#building-the-android-app), exact NDK 23 version obtained from `sdkmanager --list`)
  1. Set up the environment variables:
     ```
     export ANDROID_NDK_HOME=~/Android/Sdk/ndk/23.1.7779620 ANDROID_HOME=~/Android/Sdk
     ```
- [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gobind) (installed as needed by `make`)

### Apple (iOS and macOS)

- Xcode
- [gomobile](https://pkg.go.dev/golang.org/x/mobile/cmd/gobind) (installed as needed by `make`)

### Linux and Windows

We build binaries for Linux and Windows from source without any custom integrations.
`xgo` and Docker are required to support cross-compilation.

- [Docker](https://docs.docker.com/get-docker/) (for XGO)
- [xgo](https://github.com/crazy-max/xgo) (installed as needed by `make`)
- [ghcr.io/crazy-max/xgo Docker image](https://github.com/crazy-max/xgo/pkgs/container/xgo) (~6.8GB pulled by `xgo`).

## Make

```
# iOS and macOS: This will create build/apple/Tun2socks.xcframework
make clean && make apple

# Linux: This will create build/linux/tun2socks
make clean && make linux

# For Windows: This will create build/windows/tun2socks.exe
make clean && make windows

# For Android: This will create build/android/{tun2socks.aar,tun2socks-sources.jar}
make clean && make android

# For Intra: This will create build/intra/{tun2socks.aar,tun2socks-sources.jar}
make clean && make intra

```
If needed, you can extract the jni files into `build/android/jni` with:
```bash
unzip build/android/tun2socks.aar 'jni/*' -d build/android
```
