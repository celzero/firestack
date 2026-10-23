package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/celzero/firestack/intra"
	"github.com/celzero/firestack/intra/backend"
	"github.com/celzero/firestack/intra/settings"
	"github.com/celzero/firestack/linux-tool/glue"
)

func p(e error) {
	if e != nil {
		panic(e)
	}
}
func sendTUN(name string) {
	sock := int(3)
	defer syscall.Close(sock)
	syscall.SetNonblock(sock, true)
	tun, err := glue.OpenTUN(name)
	p(err)
	defer syscall.Close(tun)

	ifInfo, err := net.InterfaceByName(name)
	p(err)
	var msg [4]byte
	binary.NativeEndian.PutUint32(msg[:], uint32(ifInfo.MTU))
	cmsg := glue.GenFDCmsg([]uint32{uint32(tun)})
	err = syscall.Sendmsg(sock, msg[:], cmsg, nil, 0)
	p(err)
}
func demo(targetPid int, tunName string, fakeDNS string) {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	p(err)
	defer func() {
		syscall.Close(pair[0])
		syscall.Close(pair[1])
	}()
	syscall.SetNonblock(pair[0], true)

	elfPath, err := os.Executable()
	p(err)
	c1 := exec.Command("/usr/bin/nsenter", "--target", fmt.Sprintf("%d", targetPid), "--user", "--net",
		"--preserve-credentials", "--keep-caps",
		elfPath, "-mode", "sendfd", "-tun", tunName)
	c1.ExtraFiles = []*os.File{os.NewFile(uintptr(pair[1]), "")}
	fmt.Println("starting child...")
	output, err := c1.CombinedOutput()
	if len(output) > 0 {
		fmt.Printf("child's output:\n%s\n", string(output))
	}
	p(err)

	var buf [4]byte
	var cmsgBuf [20]byte
	n, cmsgN, msgFlag, _, err := syscall.Recvmsg(pair[0], buf[:], cmsgBuf[:], 0)
	p(err)
	fmt.Printf("msg: %v\ncmsg: %v\nflag: %d\n", buf[:n], cmsgBuf[:cmsgN], msgFlag)
	tun := int(binary.NativeEndian.Uint32(cmsgBuf[16:]))
	defer syscall.Close(tun)
	mtu := binary.NativeEndian.Uint32(buf[:])

	settings.SetDialerOpts(settings.SplitDesync, settings.RetryNever, 0, false)
	bridge := glue.MyBridge{
		PIDCSV: backend.Base,
		TIDCSV: backend.Preferred,
	}
	tunnel, err := intra.NewTunnel(tun, int(mtu), fakeDNS, nil, &bridge)
	p(err)
	defer tunnel.Disconnect()

	err = intra.AddDoHTransport(tunnel, backend.Preferred, "https://[2620:fe::12]/dns-query", "2620:fe::12")
	p(err)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	wait1 := <-ch
	fmt.Printf("received %v signal, exiting\n", wait1)
}
func main() {
	var mode string
	flag.StringVar(&mode, "mode", "main", "main or sendfd")
	var tunName string
	flag.StringVar(&tunName, "tun", "tun0", "")
	var pid int
	flag.IntVar(&pid, "target", -1, "target process to get namespaces from")
	var fakeDNS string
	flag.StringVar(&fakeDNS, "dns", "10.0.2.3:53", "DNS passed to intra.NewTunnel()")
	flag.Parse()

	switch mode {
	case "main":
		demo(pid, tunName, fakeDNS)
	case "sendfd":
		sendTUN(tunName)
	default:
		fmt.Printf("unknown mode: %s\n", mode)
	}
}
