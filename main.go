package main

import (
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"math/rand"
	"net"
	"time"
)

func NewPinger(host string) (*Pinger, error) {
	p := &Pinger{}
	err := p.SetAddr(host)
	if err != nil {
		return nil, err
	}
	return p, nil
}

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

func (p *Pinger) Run() {
	conn, err := icmp.ListenPacket("ip4:icmp", p.sourceAddr)
	if err != nil {
		fmt.Printf("ListenPacket error %s\n", err)
		return
	}

	// 不断 发送和接收
	// 接收
	go func() {
		for {
			bytesGot := make([]byte, 512)
			n, _, err := conn.ReadFrom(bytesGot)
			if err != nil {
				return
			}

			rm, err := icmp.ParseMessage(1, bytesGot[:n])
			if err != nil {
				return
			}

			pkt := rm.Body.(*icmp.Echo)
			Rtt := time.Since(bytesToTime(pkt.Data[:8]))
			fmt.Printf("RTT is %s\n", Rtt)
		}
	}()

	// 发送
	for {
		bytes, err := (&icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID:   rand.Intn(65535),
				Seq:  1,
				Data: timeToBytes(time.Now()),
			},
		}).Marshal(nil)
		if err != nil {
			time.Sleep(time.Second * 10)
			continue
		}

		_, err = conn.WriteTo(bytes, p.ipaddr)
		// length, err := conn.WriteTo(bytes, &net.IPAddr{IP: net.IPv4(192, 168, 1, 93)})
		if err != nil {
			time.Sleep(time.Second * 10)
			continue
		}

		time.Sleep(time.Second * 10)
	}
}

var usage = `
Usage:
    ping host
Examples:
    # ping google continuously
    ping www.google.com
`

func main() {
	flag.Usage = func() {
		fmt.Printf(usage)
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		return
	}
	host := flag.Arg(0)
	pinger, err := NewPinger(host)
	if err != nil {
		fmt.Printf("ERROR: %s\n", err.Error())
		return
	}

	fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
	pinger.Run()
}

func timeToBytes(t time.Time) []byte {
	nsec := t.UnixNano()
	b := make([]byte, 8)
	for i := uint8(0); i < 8; i++ {
		b[i] = byte((nsec >> ((7 - i) * 8)) & 0xff)
	}
	return b
}

func bytesToTime(b []byte) time.Time {
	var nsec int64
	for i := uint8(0); i < 8; i++ {
		nsec += int64(b[i]) << ((7 - i) * 8)
	}
	return time.Unix(nsec/1000000000, nsec%1000000000)
}
