# jing
[![GoDoc](https://godoc.org/github.com/caser789/jing?status.svg)](https://godoc.org/github.com/caser789/jing)

ICMP Ping library for Go, inspired by
[go-fastping](https://github.com/tatsushid/go-fastping)
Here is a very simple example that sends & receives 3 packets:
```go
 pinger, err := ping.NewPinger("www.google.com")
 if err != nil {
     panic(err)
 }
 pinger.Count = 3
 pinger.Run() // blocks until finished
 stats := pinger.Statistics() // get send/receive/rtt stats
```
Here is an example that emulates the unix ping command:
```go
 pinger, err := ping.NewPinger("www.google.com")
 if err != nil {
     fmt.Printf("ERROR: %s\n", err.Error())
     return
 }
 pinger.OnRecv = func(pkt *ping.Packet) {
     fmt.Printf("%d bytes from %s: icmp_seq=%d time=%v\n",
         pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt)
 }
 pinger.OnFinish = func(stats *ping.Statistics) {
     fmt.Printf("\n--- %s ping statistics ---\n", stats.Addr)
     fmt.Printf("%d packets transmitted, %d packets received, %v%% packet loss\n",
         stats.PacketsSent, stats.PacketsRecv, stats.PacketLoss)
     fmt.Printf("round-trip min/avg/max/stddev = %v/%v/%v/%v\n",
         stats.MinRtt, stats.AvgRtt, stats.MaxRtt, stats.StdDevRtt)
 }
 fmt.Printf("PING %s (%s):\n", pinger.Addr(), pinger.IPAddr())
 pinger.Run()
```
It sends ICMP packet(s) and waits for a response. If it receives a response,
it calls the "receive" callback. When it's finished, it calls the "finish"
callback.


## Installation:

```
go get https://github.com/caser789/jing
```

To install the native Go ping executable:

```bash
go get github.com/caser789/jing/...
$GOPATH/bin/ping
```

## Note on Linux Support:

This library attempts to send an
"unprivileged" ping via UDP. On linux, this must be enabled by setting
```
sudo sysctl -w net.ipv4.ping_group_range="0   2147483647"
```
>       ping_group_range (two integers; default: see below; since Linux
>       2.6.39)
>              Range of the group IDs (minimum and maximum group IDs,
>              inclusive) that are allowed to create ICMP Echo sockets.
>              The default is "1 0", which means no group is allowed to
>              create ICMP Echo sockets.
* [ICMP man page](https://man7.org/linux/man-pages/man7/icmp.7.html)
use setcap to allow your binary using go-ping to bind to raw sockets
(or just run as super-user):

```
setcap cap_net_raw=+ep /bin/jing-binary
```
If you do not wish to do this, you can set `pinger.SetPrivileged(true)` and
run as super-user.
See [this blog](https://sturmflut.github.io/linux/ubuntu/2015/01/17/unprivileged-icmp-sockets-on-linux/)
and [the Go icmp library](https://godoc.org/golang.org/x/net/icmp) for more details.
