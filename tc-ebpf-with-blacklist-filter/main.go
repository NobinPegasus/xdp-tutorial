// tshark -i vpns0 -V --print -S "======================================================================================="

package main

// from https://d0u9.io/use-cilium-ebpf-to-compile-and-load-tc-bpf-code/

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"os/signal"
	"path/filepath"
	"sort"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tc bpf/bpf.c -- -I./bpf

type TaggedIpList struct {
	Tag       string
	Addresses []uint32
}

// ---------------------------

// ip2int converts an IP address from string to a uint32
func ip2int(ip string) (uint32, error) {
	bytes := net.ParseIP(ip)
	if bytes == nil {
		return 0, errors.New("invalid IP address format")
	}
	bytes = bytes.To4()
	if bytes == nil {
		return 0, errors.New("invalid IPv4 address format")
	}
	return uint32(bytes[0])<<24 + uint32(bytes[1])<<16 + uint32(bytes[2])<<8 + uint32(bytes[3]), nil
}

// -------------------------------

func NewTaggedIpList(tag string, filePath string) (*TaggedIpList, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var addresses []uint32
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		intIP, err := ip2int(line)
		if err != nil {
			continue // if the IP conversion fails, skip this line
		}
		addresses = append(addresses, intIP)
	}

	// Sort addresses
	sort.Slice(addresses, func(i, j int) bool { return addresses[i] < addresses[j] })

	return &TaggedIpList{
		Tag:       tag,
		Addresses: addresses,
	}, scanner.Err()
}

// // Helper function to convert uint32 IP back to human-readable format
func intToIP(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		ip>>24,        // Extract the first 8 bits
		(ip>>16)&0xFF, // Extract the next 8 bits
		(ip>>8)&0xFF,  // Extract the next 8 bits
		ip&0xFF)       // Extract the last 8 bits
}

func InttoIP4(ipInt uint32) string {
	// fmt.Printf("IP: %d", ipInt)
	// need to do two bit shifting and “0xff” masking
	b0 := strconv.FormatInt(int64((ipInt>>24)&0xff), 10)
	b1 := strconv.FormatInt(int64((ipInt>>16)&0xff), 10)
	b2 := strconv.FormatInt(int64((ipInt>>8)&0xff), 10)
	b3 := strconv.FormatInt(int64((ipInt & 0xff)), 10)
	return b0 + "." + b1 + "." + b2 + "." + b3
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8) | (value >> 8)
}

// =========================

const INTERFACE = "vpns0"

func main() {
	var err error
	// Allow the current process to lock memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memory lock: %v", err)
	}

	// Define command-line argument with a default value of "print"
	// blockMode := flag.String("block", "print", "Action mode: print, dump, suspend, kill")
	// flag.Parse()

	// Load bpf programs and maps into the kernel
	objs := tcObjects{}
	if err := loadTcObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	progFd := objs.TcMain.FD()

	intf, err := netlink.LinkByName(INTERFACE)
	if err != nil {
		log.Fatalf("cannot find %s: %v", INTERFACE, err)
	}

	attrs := netlink.QdiscAttrs{
		LinkIndex: intf.Attrs().Index, //Interface index
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	// declare the qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	// add the qdisc
	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Fatalf("cannot add clsact qdisc: %v", err)
	}

	//filter attributes
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: intf.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_INGRESS, //direction
		// Parent:   netlink.HANDLE_MIN_EGRESS,
		Handle:   netlink.MakeHandle(0, 1),
		Protocol: unix.ETH_P_ALL,
		Priority: 1,
	}

	//declare the BPF filter
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterAttrs,
		Fd:           progFd,
		Name:         "hi-tc",
		DirectAction: true,
	}

	//add the filter
	if err := netlink.FilterAdd(filter); err != nil {
		log.Fatalf("cannot attach bpf object to filter: %v", err)
	}

	log.Printf("Counting packets on %s...", INTERFACE)

	//repeatedly output the map contents
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
	pktCount := objs.PktCount

	// ===============
	// Initialize a slice to hold the TaggedIpLists
	var lists []*TaggedIpList

	// Define the path to the directory and pattern for the files
	path := "ip_feeds"
	pattern := "*.txt"

	// List all text files in the specified directory
	files, err := filepath.Glob(filepath.Join(path, pattern))
	if err != nil {
		log.Fatalf("Failed to list files: %v", err)
	}

	// Check if no files are found
	if len(files) == 0 {
		log.Fatalf("No feeds available. Run update_feeds.sh!")
	}

	// Iterate over each file only once
	for _, file := range files {
		tagIpList, err := NewTaggedIpList(filepath.Base(file), file)
		if err != nil {
			log.Printf("Failed to create TaggedIpList from %s: %v", file, err)
			continue
		}
		lists = append(lists, tagIpList)
	}

	// Assume we have a map called "ip_blacklist"
	blacklist := objs.IpBlacklist

	// Load bad IPs from a file (already part of your existing setup)
	for _, list := range lists {
		// fmt.Println(len(list.Addresses))
		for _, badIP := range list.Addresses {
			// fmt.Println(InttoIP4(badIP))
			ipKey := badIP       // Your eBPF map might expect the network byte order
			ipValue := uint32(1) // The value is just a dummy to indicate presence in the map
			if err := blacklist.Put(ipKey, ipValue); err != nil {
				log.Printf("Failed to insert bad IP into the blacklist: %v", err)
			}
		}
	}
	// ===================================

	for {
		select {
		case <-tick:
			// log.Printf("================================================")
			var (
				entries    = pktCount.Iterate()
				packetdets tcPacketdets
				count      uint64
			)
			for entries.Next(&packetdets, &count) {
				source := InttoIP4(packetdets.Source)
				source_port := packetdets.SourcePort
				dest := InttoIP4(packetdets.Dest)
				dest_port := packetdets.DestPort
				ip_protocol := packetdets.IpProtocol

				if ip_protocol == 6 {
					log.Printf("%s[%d] -> %s[%d] proto %d: %d", source, ntohs(source_port), dest, ntohs(dest_port), ip_protocol, count)
					log.Printf("================================================")
				}

			}
			log.Printf("")

		case <-stop:
			log.Printf("Received signal stopping.")
			return
		}
	}
}

