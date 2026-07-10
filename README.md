# Firestack

Firestack is a userspace TCP/UDP connection monitor, firewall, DNS resolver, and multi-hop [WireGuard](https://github.com/wireguard/wireguard-go) client for Android.

Firestack is built specifically for [Rethink DNS + Firewall + VPN](https://github.com/celzero/rethink-app). [gVisor/netstack](https://github.com/google/gvisor/tree/go/pkg/tcpip) provides a SOCKS-like interface (similar to [badvpn's tun2socks](https://github.com/ambrop72/badvpn)) for TCP/UDP over a TUN device.

Firestack is a hard-fork of Google's [outline-go-tun2socks](https://github.com/Jigsaw-Code/outline-go-tun2socks) project.

## DNS

Firestack supports DNS over HTTPS, DNS over TLS, Oblivious DNS over HTTPS, DNS over WireGuard / SOCKS5 / Tor, DNSCrypt, and plain old DNS upstreams.

## WireGuard

Firestack runs WireGuard in userspace. When running *multiple* WireGuard tunnels at once, only ICMP, DNS, TCP and UDP are forwarded through them. ARP / IGMP / SCTP / RTP and other IP protocols are *not* forwarded to WireGuard tunnels.

Firestack supports multi-hop / multi-relay WireGuard, where multiple tunnels can be chained together, provided that the outer tunnel (hop/relay) can route to the inner tunnel's (exit) endpoint.

[<img src="https://fossunited.org/files/fossunited-white.svg"
     alt="FOSS United"
     height="40">](https://fossunited.org/grants)&emsp;<a href="https://floss.fund"><img src="https://floss.fund/static/badge.svg" alt="FLOSS/fund badge" /></a>

WireGuard integration was sponsored by [FOSS United](https://fossunited.org/grants); and Multi-hop / Multi-relay WireGuard by [FLOSS/fund](https://floss.fund/).

## Releases

[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://slsa.dev/spec/v1.2/build-track-basics#build-l3) [![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/celzero/firestack/badge)](https://securityscorecards.dev/viewer/?uri=github.com/celzero/firestack) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11568/badge)](https://www.bestpractices.dev/projects/11568) [![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/celzero/firestack)

Firestack is released as an Android Library (`aar`) and can be integrated into
your Android builds via [Jitpack](https://jitpack.io/#celzero/firestack) ([ref](https://github.com/celzero/rethink-app/commit/a6e2abca7)) or [Maven Central (OSSRH)](https://central.sonatype.com/artifact/com.celzero/firestack/overview).

```gradle
    // add this to your project's build.gradle
    allprojects {
        repositories {
            ...
            // if consuming from maven central
            // ref: central.sonatype.org/consume
            mavenCentral()
            ...
            // if consuming from jitpack
            // ref: docs.jitpack.io/android/#installing
            maven { url 'https://jitpack.io' }
            ...
        }
    }

    // add the dep to your app's build.gradle
    dependencies {
        ...
        // maven central (stripped)
        implementation 'com.celzero:firestack:Tag@aar'
        ...
        // jitpack (stripped)
        implementation 'com.github.celzero:firestack:Tag@aar'
        // jitpack (debug symbols)
        implementation 'com.github.celzero:firestack:Tag:debug@aar'
        ...
    }
```

## API

The APIs aren't stable and hence left undocumented, but you can look at
Rethink DNS + Firewall + VPN codebase: ([GoVpnAdapter](https://github.com/celzero/rethink-app/blob/v0.5.5y/app/src/main/java/com/celzero/bravedns/net/go/GoVpnAdapter.kt#L123-L151), [BraveVpnService](https://github.com/celzero/rethink-app/blob/v0.5.5y/app/src/main/java/com/celzero/bravedns/service/BraveVPNService.kt#L5203-L5376)) to see how to integrate with Firestack on Android.

## Build

Firestack only supports Android. Instructions for other platforms are left as-is, but they may or may not work.

### Prerequisites

- macOS host (iOS, macOS)
- make
- Go >= 1.26
- A C compiler (e.g.: clang, gcc)

Firestack APIs are available only on Android builds for now. iOS and Linux support planned but nothing concrete yet.

### Android

- [sdkmanager](https://developer.android.com/studio/command-line/sdkmanager)
  1. Download the command line tools from [developer.android.com](https://developer.android.com/studio).
  1. Unzip the pacakge as `~/Android/Sdk/cmdline-tools/latest/`. Make sure `sdkmanager` is located at `~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager`
- Android NDK 28+
  ```bash
  # Install the NDK (exact NDK version obtained from `sdkmanager --list`)
  ~/Android/Sdk/cmdline-tools/latest/bin/sdkmanager "platforms;android-36" "ndk;28.2.13676358"
  # Set up the environment variables:
  export ANDROID_NDK_HOME=~/Android/Sdk/ndk/28.2.13676358 ANDROID_HOME=~/Android/Sdk
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
# creates build/intra/{tun2socks.aar,tun2socks-sources.jar}
make clean && make intra

```
If needed, you can extract the jni files into `build/android/jni` with:
```bash
unzip build/android/tun2socks.aar 'jni/*' -d build/android
```
