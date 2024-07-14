package main

import (
	"flag"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/gorilla/websocket"
)

var addr = flag.String("addr", "localhost:8080", "http service address")

var upgrader = websocket.Upgrader{} // use default options
var objs counterObjects

func echo(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Print("upgrade:", err)
		return
	}
	defer c.Close()
	stop := make(chan bool, 1)

	for {
		mt, message, err := c.ReadMessage()
		if err != nil {
			log.Println("read:", err)
			break
		}
		updateTicker := time.NewTicker(1 * time.Second)
		for {
			select {
			case <-updateTicker.C:
				s, err := formatMapContents(objs.PktCount)
				if err != nil {
					log.Printf("Error reading map: %s", err)
				}
				log.Printf("recv: %d | %s", mt, message)
				err = c.WriteJSON(s)
				if err != nil {
					stop <- true
					log.Println("write:", err)
					break
				}
			case <-stop:
				return
			}
		}

	}
}

func main() {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel.

	if err := loadCounterObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "eth0" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	// Attach count_packets to the network interface.
	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpPass,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	log.Printf("Counting incoming packets on %s..", ifname)
	upgrader.CheckOrigin = func(r *http.Request) bool { return true }

	http.HandleFunc("/echo", echo)

	flag.Parse()
	log.SetFlags(0)
	http.ListenAndServe(*addr, nil)
}

func formatMapContents(m *ebpf.Map) (map[string]int, error) {
	var (
		rmap = make(map[string]int)
		key  netip.Addr
		val  uint64
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := key // IPv4 source address in network byte order.
		packetCount := val
		val, err := net.LookupAddr(sourceIP.String())
		if err == nil {
			rmap[val[0]] = int(packetCount)
		}
	}
	return rmap, iter.Err()
}
