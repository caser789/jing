package main

import (
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"math/rand"
	"net"
)

type Pinger struct {
	sourceAddr string
	addr       string
	ipaddr     *net.IPAddr
}

func (p *Pinger) SetAddr(addr string) error {
	ipaddr, err := net.ResolveIPAddr("ip4:icmp", addr)
	if err != nil {
		return err
	}
	p.addr = addr
	p.ipaddr = ipaddr
	return nil
}
func (p *Pinger) Addr() string { return p.addr }

func (p *Pinger) SetIPAddr(ipaddr *net.IPAddr) {
	p.ipaddr = ipaddr
	p.addr = ipaddr.String()
}
func (p *Pinger) IPAddr() *net.IPAddr { return p.ipaddr }

func (p *Pinger) Run() error {
	conn, err := icmp.ListenPacket("ip4:icmp", p.sourceAddr)
	if err != nil {
		return err
	}

	bytes, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   rand.Intn(65535),
			Seq:  1,
			Data: []byte{11, 22},
		},
	}).Marshal(nil)
	if err != nil {
		return err
	}
	fmt.Printf("bytes sent %s\n", bytes)
	length, err := conn.WriteTo(bytes, p.ipaddr)
	// length, err := conn.WriteTo(bytes, &net.IPAddr{IP: net.IPv4(192, 168, 1, 93)})
	if err != nil {
		return err
	}

	bytesGot := make([]byte, 512)
	n, _, err := conn.ReadFrom(bytesGot)
	if err != nil {
		return err
	}
	fmt.Printf("bytes received %s, %d\n", bytesGot, n)
	rm, err := icmp.ParseMessage(1, bytesGot[:n])
	if err != nil {
		return err
	}
	fmt.Printf("bytes received %v, %d\n", rm, n)

	fmt.Printf("conn write to length %d\n", length)
	return nil
}

func main() {
	pinger := &Pinger{}
	err := pinger.SetAddr("www.google.com")
	if err != nil {
		fmt.Printf("set addr err: %s\n", err)
		return
	}
	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())

	err = pinger.Run()
	fmt.Printf("run error %s", err)
}
