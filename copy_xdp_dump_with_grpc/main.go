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
		Seq             uint32
		AckSeq          uint32
		NS              uint8
		Reserved        uint8
		Doff            uint8
		Fin             uint8
		Syn             uint8
		Rst             uint8
		Psh             uint8
		Ack             uint8
		Urg             uint8
		Ece             uint8
		Cwr             uint8
		Window          uint16
		Check           uint16
		UrgPtr          uint16
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

			fmt.Printf("TCP: Source MAC: %s -> %s %d\n",
				ByteToMAC(event.EthernetHeader.SourceMAC), ByteToMAC(event.EthernetHeader.DestinationMAC), event.EthernetHeader.EtherType,
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
			// fmt.Printf("TCP: SourcePort:%d\nDestinationPort:%d\nSeq:%d\nAckSeq:%d\nDoff:%d\nNS:%d\nReserved:%d\nFin:%d\nSyn:%d\nRst:%d\nPsh:%d\nAck:%d\nUrg:%d\nEce:%d\nCwr:%d\nWindow:%d\nCheck:%d\nUrgPtr:%d\n",
			// 	ntohs(event.TCPHeader.SourcePort),
			// 	ntohs(event.TCPHeader.DestinationPort),
			// 	event.TCPHeader.Seq,
			// 	event.TCPHeader.AckSeq,
			// 	event.TCPHeader.Doff,
			// 	event.TCPHeader.NS,
			// 	event.TCPHeader.Reserved,
			// 	event.TCPHeader.Fin,
			// 	event.TCPHeader.Syn,
			// 	event.TCPHeader.Rst,
			// 	event.TCPHeader.Psh,
			// 	event.TCPHeader.Ack,
			// 	event.TCPHeader.Urg,
			// 	event.TCPHeader.Ece,
			// 	event.TCPHeader.Cwr,
			// 	event.TCPHeader.Window,
			// 	event.TCPHeader.Check,
			// 	event.TCPHeader.UrgPtr,
			// )

			// fmt.Printf("%+v\n", event.TCPHeader)

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
				fmt.Println(hex.Dump(evnt.RawSample[METADATA_SIZE:]))
				rawData = evnt.RawSample[METADATA_SIZE:]
			}

			received += len(evnt.RawSample)
			lost += int(evnt.LostSamples)

			// Send data to gRPC server
			err = sendDataToServer(client, int32(counter), event, hex.Dump(rawData))
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

func sendDataToServer(client pb.UserServiceClient, packetNumber int32, event perfEventItem, rawDumpString string) error {
	// Create gRPC message types for TCP, IP, and Ethernet headers
	ipHeader := &pb.IpHeader{
		SourceIp:      event.IPHeader.SourceIP,
		DestinationIp: event.IPHeader.DestinationIP,
		Version:       uint32(event.IPHeader.Version),
		Protocol:      uint32(event.IPHeader.Protocol),
		Check:         uint32(event.IPHeader.Checksum),
		Ihl:           uint32(event.IPHeader.IHL),
		FragOff:       uint32(event.IPHeader.FragmentOff),
		Id:            uint32(event.IPHeader.ID),
		Tos:           uint32(event.IPHeader.TOS),
		Ttl:           uint32(event.IPHeader.TTL),
		TotLen:        uint32(event.IPHeader.TotalLength),
	}
	tcpHeader := &pb.TcpHeader{
		SourcePort:      uint32(event.TCPHeader.SourcePort),
		DestinationPort: uint32(event.TCPHeader.DestinationPort),
		Seq:             event.TCPHeader.Seq,
		AckSeq:          event.TCPHeader.AckSeq,
		Doff:            uint32(event.TCPHeader.Doff),
		Ns:              []byte{event.TCPHeader.NS},
		Reserved:        []byte{event.TCPHeader.Reserved},
		Fin:             []byte{event.TCPHeader.Fin},
		Syn:             []byte{event.TCPHeader.Syn},
		Rst:             []byte{event.TCPHeader.Rst},
		Psh:             []byte{event.TCPHeader.Psh},
		Ack:             []byte{event.TCPHeader.Ack},
		Urg:             []byte{event.TCPHeader.Urg},
		Ece:             []byte{event.TCPHeader.Ece},
		Cwr:             []byte{event.TCPHeader.Cwr},
		Window:          uint32(event.TCPHeader.Window),
		Check:           uint32(event.TCPHeader.Check),
		UrgPtr:          uint32(event.TCPHeader.UrgPtr),
	}
	ethernetHeader := &pb.EthernetHeader{
		EtherType:      uint32(event.EthernetHeader.EtherType),
		DestinationMac: event.EthernetHeader.DestinationMAC[:],
		SourceMac:      event.EthernetHeader.SourceMAC[:],
	}

	// Send data to server
	_, err := client.SendUserData(context.Background(), &pb.UserRequest{
		IpHeader:       ipHeader,
		TcpHeader:      tcpHeader,
		EthernetHeader: ethernetHeader,
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
