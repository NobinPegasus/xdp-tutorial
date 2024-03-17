package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	pb "github.com/inspektors-io/grpc-nobin/grpc-test" // Update with your actual package name

	"google.golang.org/grpc"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang XdpDump ./bpf/xdp_dump.c -- -I../header

var (
	iface string
	conn  *grpc.ClientConn
)

const (
	METADATA_SIZE = 12
)

type Collect struct {
	Prog    *ebpf.Program `ebpf:"xdp_dump"`
	PerfMap *ebpf.Map     `ebpf:"perfmap"`
}

type perfEventItem struct {
	EthernetHeader struct {
		DestinationMAC [6]byte
		SourceMAC      [6]byte
		EtherType      uint16
	}
	IPHeader struct {
		SourceIP      uint32
		DestinationIP uint32
		Version       uint8
		IHL           uint8
		TOS           uint8
		TotalLength   uint16
		ID            uint16
		FragmentOff   uint16
		TTL           uint8
		Protocol      uint8
		Checksum      uint16
	}
	TCPHeader struct {
		SourcePort      uint16
		DestinationPort uint16
		Sequence        uint32
		Acknowledgment  uint32
		Flags           uint16 // Instead of using individual bool flags, use a single field to represent all TCP flags
		Window          uint16
		Checksum        uint16
		UrgentPointer   uint16
	}
}

func main() {
	flag.StringVar(&iface, "iface", "", "interface attached xdp program")
	flag.Parse()

	if iface == "" {
		fmt.Println("interface is not specified.")
		os.Exit(1)
	}

	link, err := netlink.LinkByName(iface)
	if err != nil {
		fmt.Printf("Failed to get interface by name: %v\n", err)
		os.Exit(1)
	}

	spec, err := LoadXdpDump()
	if err != nil {
		fmt.Printf("Failed to load XDP dump: %v\n", err)
		os.Exit(1)
	}

	var collect = &Collect{}
	if err := spec.LoadAndAssign(collect, nil); err != nil {
		fmt.Printf("Failed to load and assign XDP program: %v\n", err)
		os.Exit(1)
	}

	if err := netlink.LinkSetXdpFdWithFlags(link, collect.Prog.FD(), nl.XDP_FLAGS_SKB_MODE); err != nil {
		fmt.Printf("Failed to attach XDP program to interface: %v\n", err)
		os.Exit(1)
	}

	defer func() {
		if err := netlink.LinkSetXdpFdWithFlags(link, -1, nl.XDP_FLAGS_SKB_MODE); err != nil {
			fmt.Printf("Error detaching program: %v\n", err)
		}
	}()

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	perfEvent, err := perf.NewReader(collect.PerfMap, 4096)
	if err != nil {
		fmt.Printf("Failed to create perf event reader: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("All new TCP connection requests (SYN) coming to this host will be dumped here.")
	fmt.Println()

	var (
		received int = 0
		lost     int = 0
		counter  int = 0
	)

	// Connect to gRPC server
	conn, err = grpc.Dial("localhost:50051", grpc.WithInsecure())
	if err != nil {
		fmt.Printf("Failed to connect to gRPC server: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Create gRPC client
	client := pb.NewUserServiceClient(conn)

	go func() {
		var event perfEventItem
		for {
			evnt, err := perfEvent.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					break
				}
				fmt.Printf("Error reading perf event: %v\n", err)
				continue
			}

			reader := bytes.NewReader(evnt.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
				fmt.Printf("Error decoding perf event: %v\n", err)
				continue
			}

			fmt.Printf("TCP: %s:%d -> %s:%d\n",
				intToIPv4(event.IPHeader.SourceIP), ntohs(event.TCPHeader.SourcePort),
				intToIPv4(event.IPHeader.DestinationIP), ntohs(event.TCPHeader.DestinationPort),
			)

			// fmt.Printf("=====================================================\n")
			// // IP Header informations
			// fmt.Printf("IP: SourceIP:%s\nDestinationIP:%s\nVersion:%d\nProtocol:%d\nChecksum:%d\nFragmentOff:%d\nID:%d\nIHL:%d\nTOS:%d\nTTL:%d\nTotalLength:%d\n",
			// 	intToIPv4(event.IPHeader.SourceIP),
			// 	intToIPv4(event.IPHeader.DestinationIP),
			// 	event.IPHeader.Version,
			// 	event.IPHeader.Protocol,
			// 	event.IPHeader.Checksum,
			// 	event.IPHeader.FragmentOff,
			// 	event.IPHeader.ID,
			// 	event.IPHeader.IHL,
			// 	event.IPHeader.TOS,
			// 	event.IPHeader.TTL,
			// 	event.IPHeader.TotalLength,
			// )

			// fmt.Printf("=====================================================\n")
			// // TCP Header informations
			// fmt.Printf("TCP: Acknowledgment:%d\nChecksum:%d\nDestinationPort:%d\nFlags:%d\nSequence:%d\nSourcePort:%d\nUrgentPointer:%d\nWindow:%d\n",
			// 	event.TCPHeader.Acknowledgment,
			// 	event.TCPHeader.Checksum,
			// 	ntohs(event.TCPHeader.DestinationPort),
			// 	event.TCPHeader.Flags,
			// 	event.TCPHeader.Sequence,
			// 	ntohs(event.TCPHeader.SourcePort),
			// 	event.TCPHeader.UrgentPointer,
			// 	event.TCPHeader.Window,
			// )

			// fmt.Printf("=====================================================\n")
			// // Ethernet Header informations
			// fmt.Printf("Ethernet: EtherType:%d\nDestinationMAC:%s\nSourceMAC:%s\n",
			// 	event.EthernetHeader.EtherType,
			// 	ByteToMAC(event.EthernetHeader.DestinationMAC),
			// 	ByteToMAC(event.EthernetHeader.SourceMAC),
			// )

			counter++
			fmt.Printf("Counter: %d\n", counter)

			rawData := evnt.RawSample[METADATA_SIZE:]

			if len(evnt.RawSample)-METADATA_SIZE > 0 {
				// fmt.Println(hex.Dump(evnt.RawSample[METADATA_SIZE:]))
				rawData = evnt.RawSample[METADATA_SIZE:]
			}

			received += len(evnt.RawSample)
			lost += int(evnt.LostSamples)

			// Send data to gRPC server
			err = sendDataToServer(client, int32(counter), hex.Dump(rawData))
			if err != nil {
				fmt.Printf("Failed to send data to gRPC server: %v\n", err)
				continue
			}
			fmt.Println("Data sent successfully to gRPC server")

		}
	}()

	<-ctrlC
	perfEvent.Close()

	fmt.Println("\nSummary:")
	fmt.Printf("\t%d Event(s) Received\n", received)
	fmt.Printf("\t%d Event(s) Lost(e.g. small buffer, delays in processing)\n", lost)
	fmt.Println("\nDetaching program and exiting...")
}

func sendDataToServer(client pb.UserServiceClient, packetNumber int32, rawDumpString string) error {
	// Send data to server
	_, err := client.SendUserData(context.Background(), &pb.UserRequest{
		IpHeader:       &pb.IpHeader{},
		TcpHeader:      &pb.TcpHeader{},
		EthernetHeader: &pb.EthernetHeader{},
		PacketNumber:   packetNumber,
		RawData:        rawDumpString,
	})
	return err
}

func intToIPv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}

func ntohs(value uint16) uint16 {
	return ((value & 0xff) << 8) | (value >> 8)
}

func ByteToMAC(mac [6]byte) string {
	var macStrBuilder strings.Builder

	for i, b := range mac {
		if i > 0 {
			macStrBuilder.WriteString(":")
		}
		macStrBuilder.WriteString(fmt.Sprintf("%02X", b))
	}

	return macStrBuilder.String()
}
