// TODO
// handle panic: interface conversion: icmp.MessageBody is *icmp.DstUnreach, not *icmp.Echo
package main

import (
	"context"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"math"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func NewPinger(host string) (*Pinger, error) {
	p := &Pinger{stat: &Stat{}}
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

	seq  int
	stat *Stat

	packetRecv int

	Count    int
	Interval time.Duration
	Timeout  time.Duration
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

func (p *Pinger) finish() {
	stat := p.Stat()
	fmt.Printf("\n--- %s ping statistics ---\n", p.Addr())
	fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n", stat.PacketsSent, stat.PacketsRecv, stat.PacketLoss)
	fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n", stat.MinRtt, stat.AvgRtt, stat.MaxRtt, stat.StdDevRtt)
}

// Stat represent the stats of a currently running or finished
// pinger operation.
type Stat struct {
	// PacketsRecv is the number of packets received.
	PacketsRecv int

	// PacketsSent is the number of packets sent.
	PacketsSent int

	// PacketLoss is the percentage of packets lost.
	PacketLoss float64

	// Rtts is all of the round-trip times sent via this pinger.
	Rtts []time.Duration

	// MinRtt is the minimum round-trip time sent via this pinger.
	MinRtt time.Duration

	// MaxRtt is the maximum round-trip time sent via this pinger.
	MaxRtt time.Duration

	// AvgRtt is the average round-trip time sent via this pinger.
	AvgRtt time.Duration

	// SumRtt is the average round-trip time sent via this pinger.
	SumRtt time.Duration

	// SumSqrtRtt is the average round-trip time sent via this pinger.
	SumSqrtRtt time.Duration

	// StdDevRtt is the standard deviation of the round-trip times sent via
	// this pinger.
	StdDevRtt time.Duration
}

func (p *Pinger) Stat() *Stat {
	p.stat.PacketLoss = float64(p.stat.PacketsSent-p.stat.PacketsRecv) / float64(p.stat.PacketsSent) * 100
	if len(p.stat.Rtts) > 0 {
		p.stat.StdDevRtt = time.Duration(math.Sqrt(float64(p.stat.SumSqrtRtt / time.Duration(len(p.stat.Rtts)))))
	}
	return p.stat
}

func (p *Pinger) Run() {
	ctxTimeout, cancel := context.WithTimeout(context.Background(), p.Timeout)
	defer cancel()
	defer p.finish()

	conn, err := icmp.ListenPacket("ip4:icmp", p.sourceAddr)
	if err != nil {
		fmt.Printf("ListenPacket error %s\n", err)
		return
	}

	closed := make(chan interface{})

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
			p.packetRecv++
			p.stat.PacketsRecv++
			p.stat.Rtts = append(p.stat.Rtts, Rtt)
			if Rtt > p.stat.MaxRtt {
				p.stat.MaxRtt = Rtt
			}
			if p.stat.MinRtt == 0 || Rtt < p.stat.MinRtt {
				p.stat.MinRtt = Rtt
			}
			p.stat.SumRtt += Rtt
			p.stat.AvgRtt = p.stat.SumRtt / time.Duration(len(p.stat.Rtts))
			p.stat.SumSqrtRtt += (Rtt - p.stat.AvgRtt) * (Rtt - p.stat.AvgRtt)
			fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n", n, p.ipaddr, pkt.Seq, Rtt)
			if p.packetRecv == p.Count {
				close(closed)
				return
			}
		}
	}()

	_ = p.sendICMP(conn)
	interval := time.NewTicker(p.Interval)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	for {
		select {
		case <-c:
			return
		case <-ctxTimeout.Done():
			return
		case <-interval.C:
			_ = p.sendICMP(conn)
		case <-closed:
			return
		}
	}
}

func (p *Pinger) sendICMP(conn *icmp.PacketConn) error {
	bytes, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   rand.Intn(65535),
			Seq:  p.seq,
			Data: timeToBytes(time.Now()),
		},
	}).Marshal(nil)
	if err != nil {
		return err
	}
	p.seq++
	p.stat.PacketsSent++

	_, err = conn.WriteTo(bytes, p.ipaddr)
	return err
}

var usage = `
Usage:

    ping host

Examples:

    # ping google continuously
    ping www.google.com

    # ping google 5 times
    ping -c 5 www.google.com

    # ping google 5 times at 500ms intervals
    ping -c 5 -i 500ms www.google.com

    # ping google for 10 seconds
    ping -t 10s www.google.com
`

func main() {
	count := flag.Int("c", -1, "")
	interval := flag.Duration("i", time.Second, "")
	timeout := flag.Duration("t", time.Second*100000, "")
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

	pinger.Count = *count
	pinger.Interval = *interval
	pinger.Timeout = *timeout
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
