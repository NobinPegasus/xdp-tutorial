package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"

	pb "github.com/inspektors-io/grpc-nobin/grpc-test" // Update with your actual package name

	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedUserServiceServer
}

func (s *server) SendUserData(ctx context.Context, req *pb.UserRequest) (*pb.UserResponse, error) {
	// Printing received data including packet number
	fmt.Printf("Received:\nPacket Number: %d\n", req.PacketNumber)

	// Handle IP header
	fmt.Printf("Source IP: %s\nDestination IP: %s\nVersion: %d\nIHL: %d\nTOS: %d\nTotal Length: %d\nID: %d\nFragment Off: %d\nTTL: %d\nProtocol: %d\nChecksum: %d\n",
		intToIPv4(req.IpHeader.SourceIp).String(), intToIPv4(req.IpHeader.DestinationIp).String(), req.IpHeader.Version,
		req.IpHeader.Ihl, req.IpHeader.Tos, req.IpHeader.TotLen, req.IpHeader.Id,
		req.IpHeader.FragOff, req.IpHeader.Ttl, req.IpHeader.Protocol, req.IpHeader.Check)

	// Handle TCP header
	fmt.Printf("Source Port: %d\nDestination Port: %d\n", req.TcpHeader.SourcePort, req.TcpHeader.DestinationPort)

	// Handle Ethernet header
	fmt.Printf("Destination MAC: %v\nSource MAC: %v\nEtherType: %d\n",
		req.EthernetHeader.DestinationMac, req.EthernetHeader.SourceMac, req.EthernetHeader.EtherType)
	// Handle raw data
	rawData := req.RawData
	fmt.Printf("Raw Data:\n%s\n", rawData)

	return &pb.UserResponse{Message: "Data received successfully"}, nil
}

func main() {
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterUserServiceServer(s, &server{})
	log.Println("gRPC server started on port 50051")
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

func intToIPv4(ip uint32) net.IP {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, ip)
	return net.IP(res)
}
