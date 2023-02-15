package jing

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"math"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"
)

const UDP = "udp"
const IP = "ip"

func NewPinger(host string) (*Pinger, error) {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	p := &Pinger{
		stat:    &Stat{},
		network: UDP,
		closed:  make(chan interface{}),
		id:      r.Intn(math.MaxInt16),
		tracker: r.Int63n(math.MaxInt64),
	}
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

	id      int
	tracker int64
	seq     int
	stat    *Stat
	closed  chan interface{}
	lock    sync.Mutex

	packetRecv int
	network    string

	Count    int
	Interval time.Duration
	Timeout  time.Duration

	// OnRecv is called when Pinger receives and processes a packet
	OnRecv func(*Packet)

	// OnFinish is called when Pinger exits
	OnFinish func(*Stat)
}

func (p *Pinger) Stop() {
	p.lock.Lock()
	defer p.lock.Unlock()

	open := true
	select {
	case _, open = <-p.closed:
	default:
	}

	if open {
		close(p.closed)
	}
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

func (p *Pinger) SetPrivileged(privileged bool) {
	if privileged {
		p.network = IP
	} else {
		p.network = UDP
	}
}

func (p *Pinger) Privileged() bool {
	return p.network == IP
}

func (p *Pinger) finish() {
	handler := p.OnFinish
	if handler != nil {
		handler(p.Stat())
	}
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

	var proto = "ip4:icmp"
	if p.network == UDP {
		proto = "udp4"
	}

	conn, err := icmp.ListenPacket(proto, p.sourceAddr)
	if err != nil {
		fmt.Printf("Error listening for ICMP packets: %s\n", err.Error())
		return
	}
	err = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	if err != nil {
		fmt.Printf("Error listening for ICMP packets: %s\n", err.Error())
		return
	}

	recv := make(chan *packet, 5)
	var wg sync.WaitGroup
	wg.Add(1)
	go p.recvICMP(conn, recv, &wg)

	_ = p.sendICMP(conn)
	interval := time.NewTicker(p.Interval)
	defer func() {
		close(recv)
		interval.Stop()
		wg.Wait()
		p.finish()
	}()
	for {
		select {
		case <-p.closed:
			return
		case <-ctxTimeout.Done():
			p.Stop()
		case <-interval.C:
			if p.Count > 0 && p.Count <= p.stat.PacketsSent {
				continue
			}
			err = p.sendICMP(conn)
			if err != nil {
				fmt.Println("FATAL: ", err.Error())
			}
		case r := <-recv:
			err = p.processPacket(r)
			if err != nil {
				fmt.Println("FATAL: ", err.Error())
			}
		}
	}
}

type packet struct {
	bytes  []byte
	nbytes int
	ttl    int
}

func (p *Pinger) processPacket(pkt *packet) error {
	bytesGot := pkt.bytes
	n := pkt.nbytes
	payload := ipv4Payload(bytesGot[:n])
	msg, err := icmp.ParseMessage(1, payload)
	if err != nil {
		return fmt.Errorf("error parsing icmp message")
	}

	if msg.Type != ipv4.ICMPTypeEchoReply {
		// Not an echo reply, ignore it
		return nil
	}

	echo, ok := msg.Body.(*icmp.Echo)
	if !ok {
		// Very bad, not sure how this can happen
		return fmt.Errorf("error, invalid ICMP echo reply. Body type: %T, %v", echo, echo)
	}
	data := IcmpData{}
	err = json.Unmarshal(echo.Data, &data)
	if err != nil {
		return err
	}
	// If we are priviledged, we can match icmp.ID
	if p.network == IP {
		// Check if reply from same ID
		if echo.ID != p.id {
			return nil
		}
	} else {
		// If we are not priviledged, we cannot set ID - require kernel ping_table map
		// need to use contents to identify packet
		if data.Tracker != p.tracker {
			return nil
		}
	}

	Rtt := time.Since(bytesToTime(data.Bytes))
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

	handler := p.OnRecv
	if handler != nil {
		handler(&Packet{
			Rtt:    Rtt,
			IPAddr: p.ipaddr,
			Nbytes: n,
			Seq:    echo.Seq,
			Ttl:    pkt.ttl,
		})
	}

	if p.packetRecv == p.Count {
		p.Stop()
	}
	return nil
}

func (p *Pinger) recvICMP(conn *icmp.PacketConn, recv chan<- *packet, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-p.closed:
			return
		default:
			bytesGot := make([]byte, 512)
			_ = conn.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
			n, cm, _, err := conn.IPv4PacketConn().ReadFrom(bytesGot)
			if err != nil {
				if neterr, ok := err.(*net.OpError); ok {
					if neterr.Timeout() {
						// Read timeout
						continue
					} else {
						p.Stop()
						return
					}
				}
			}

			var ttl int
			if cm != nil {
				ttl = cm.TTL
			}
			recv <- &packet{bytes: bytesGot, nbytes: n, ttl: ttl}
		}
	}
}

type IcmpData struct {
	Bytes   []byte
	Tracker int64
}

func (p *Pinger) sendICMP(conn *icmp.PacketConn) error {
	data, err := json.Marshal(IcmpData{Bytes: timeToBytes(time.Now()), Tracker: p.tracker})
	if err != nil {
		return fmt.Errorf("unable to marshal data %s", err)
	}
	body := &icmp.Echo{
		ID:   p.id,
		Seq:  p.seq,
		Data: data,
	}
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: body,
	}
	bytes, err := msg.Marshal(nil)
	if err != nil {
		return err
	}

	var dst net.Addr = p.ipaddr
	if p.network == UDP {
		dst = &net.UDPAddr{IP: p.ipaddr.IP, Zone: p.ipaddr.Zone}
	}
	for {
		if _, err := conn.WriteTo(bytes, dst); err != nil {
			if neterr, ok := err.(*net.OpError); ok {
				if neterr.Err == syscall.ENOBUFS {
					continue
				}
			}
		}
		p.seq++
		p.stat.PacketsSent++
		break
	}
	return nil
}

// Packet represents a received and processed ICMP echo packet.
type Packet struct {
	// Rtt is the round-trip time it took to ping.
	Rtt time.Duration

	// IPAddr is the address of the host being pinged.
	IPAddr *net.IPAddr

	// NBytes is the number of bytes in the message.
	Nbytes int

	// Seq is the ICMP sequence number.
	Seq int

	// TTL is the TTL on the packet
	Ttl int
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

func ipv4Payload(b []byte) []byte {
	if len(b) < ipv4.HeaderLen {
		return b
	}
	hdrlen := int(b[0]&0x0f) << 2
	return b[hdrlen:]
}

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}
