// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.15.8
// source: event.proto

package grpc_test

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type EthernetHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	DestinationMac []byte `protobuf:"bytes,1,opt,name=destination_mac,json=destinationMac,proto3" json:"destination_mac,omitempty"`
	SourceMac      []byte `protobuf:"bytes,2,opt,name=source_mac,json=sourceMac,proto3" json:"source_mac,omitempty"`
	EtherType      uint32 `protobuf:"varint,3,opt,name=ether_type,json=etherType,proto3" json:"ether_type,omitempty"`
}

func (x *EthernetHeader) Reset() {
	*x = EthernetHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_event_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EthernetHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EthernetHeader) ProtoMessage() {}

func (x *EthernetHeader) ProtoReflect() protoreflect.Message {
	mi := &file_event_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EthernetHeader.ProtoReflect.Descriptor instead.
func (*EthernetHeader) Descriptor() ([]byte, []int) {
	return file_event_proto_rawDescGZIP(), []int{0}
}

func (x *EthernetHeader) GetDestinationMac() []byte {
	if x != nil {
		return x.DestinationMac
	}
	return nil
}

func (x *EthernetHeader) GetSourceMac() []byte {
	if x != nil {
		return x.SourceMac
	}
	return nil
}

func (x *EthernetHeader) GetEtherType() uint32 {
	if x != nil {
		return x.EtherType
	}
	return 0
}

type IpHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SourceIp      uint32 `protobuf:"varint,1,opt,name=source_ip,json=sourceIp,proto3" json:"source_ip,omitempty"`
	DestinationIp uint32 `protobuf:"varint,2,opt,name=destination_ip,json=destinationIp,proto3" json:"destination_ip,omitempty"`
	VersionIhl    uint32 `protobuf:"varint,3,opt,name=version_ihl,json=versionIhl,proto3" json:"version_ihl,omitempty"`
	Tos           uint32 `protobuf:"varint,4,opt,name=tos,proto3" json:"tos,omitempty"`
	TotLen        uint32 `protobuf:"varint,5,opt,name=tot_len,json=totLen,proto3" json:"tot_len,omitempty"`
	Id            uint32 `protobuf:"varint,6,opt,name=id,proto3" json:"id,omitempty"`
	FragOff       uint32 `protobuf:"varint,7,opt,name=frag_off,json=fragOff,proto3" json:"frag_off,omitempty"`
	Ttl           uint32 `protobuf:"varint,8,opt,name=ttl,proto3" json:"ttl,omitempty"`
	Protocol      uint32 `protobuf:"varint,9,opt,name=protocol,proto3" json:"protocol,omitempty"`
	Check         uint32 `protobuf:"varint,10,opt,name=check,proto3" json:"check,omitempty"`
}

func (x *IpHeader) Reset() {
	*x = IpHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_event_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IpHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IpHeader) ProtoMessage() {}

func (x *IpHeader) ProtoReflect() protoreflect.Message {
	mi := &file_event_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IpHeader.ProtoReflect.Descriptor instead.
func (*IpHeader) Descriptor() ([]byte, []int) {
	return file_event_proto_rawDescGZIP(), []int{1}
}

func (x *IpHeader) GetSourceIp() uint32 {
	if x != nil {
		return x.SourceIp
	}
	return 0
}

func (x *IpHeader) GetDestinationIp() uint32 {
	if x != nil {
		return x.DestinationIp
	}
	return 0
}

func (x *IpHeader) GetVersionIhl() uint32 {
	if x != nil {
		return x.VersionIhl
	}
	return 0
}

func (x *IpHeader) GetTos() uint32 {
	if x != nil {
		return x.Tos
	}
	return 0
}

func (x *IpHeader) GetTotLen() uint32 {
	if x != nil {
		return x.TotLen
	}
	return 0
}

func (x *IpHeader) GetId() uint32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *IpHeader) GetFragOff() uint32 {
	if x != nil {
		return x.FragOff
	}
	return 0
}

func (x *IpHeader) GetTtl() uint32 {
	if x != nil {
		return x.Ttl
	}
	return 0
}

func (x *IpHeader) GetProtocol() uint32 {
	if x != nil {
		return x.Protocol
	}
	return 0
}

func (x *IpHeader) GetCheck() uint32 {
	if x != nil {
		return x.Check
	}
	return 0
}

type TcpHeader struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	SourcePort      uint32 `protobuf:"varint,1,opt,name=source_port,json=sourcePort,proto3" json:"source_port,omitempty"`
	DestinationPort uint32 `protobuf:"varint,2,opt,name=destination_port,json=destinationPort,proto3" json:"destination_port,omitempty"`
	Seq             uint32 `protobuf:"varint,3,opt,name=seq,proto3" json:"seq,omitempty"`
	AckSeq          uint32 `protobuf:"varint,4,opt,name=ack_seq,json=ackSeq,proto3" json:"ack_seq,omitempty"`
	Flag            uint32 `protobuf:"varint,5,opt,name=flag,proto3" json:"flag,omitempty"`
	Window          uint32 `protobuf:"varint,6,opt,name=window,proto3" json:"window,omitempty"`
	Check           uint32 `protobuf:"varint,7,opt,name=check,proto3" json:"check,omitempty"`
	UrgPtr          uint32 `protobuf:"varint,8,opt,name=urg_ptr,json=urgPtr,proto3" json:"urg_ptr,omitempty"`
}

func (x *TcpHeader) Reset() {
	*x = TcpHeader{}
	if protoimpl.UnsafeEnabled {
		mi := &file_event_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TcpHeader) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TcpHeader) ProtoMessage() {}

func (x *TcpHeader) ProtoReflect() protoreflect.Message {
	mi := &file_event_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TcpHeader.ProtoReflect.Descriptor instead.
func (*TcpHeader) Descriptor() ([]byte, []int) {
	return file_event_proto_rawDescGZIP(), []int{2}
}

func (x *TcpHeader) GetSourcePort() uint32 {
	if x != nil {
		return x.SourcePort
	}
	return 0
}

func (x *TcpHeader) GetDestinationPort() uint32 {
	if x != nil {
		return x.DestinationPort
	}
	return 0
}

func (x *TcpHeader) GetSeq() uint32 {
	if x != nil {
		return x.Seq
	}
	return 0
}

func (x *TcpHeader) GetAckSeq() uint32 {
	if x != nil {
		return x.AckSeq
	}
	return 0
}

func (x *TcpHeader) GetFlag() uint32 {
	if x != nil {
		return x.Flag
	}
	return 0
}

func (x *TcpHeader) GetWindow() uint32 {
	if x != nil {
		return x.Window
	}
	return 0
}

func (x *TcpHeader) GetCheck() uint32 {
	if x != nil {
		return x.Check
	}
	return 0
}

func (x *TcpHeader) GetUrgPtr() uint32 {
	if x != nil {
		return x.UrgPtr
	}
	return 0
}

type UserRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	IpHeader       *IpHeader       `protobuf:"bytes,1,opt,name=ip_header,json=ipHeader,proto3" json:"ip_header,omitempty"`
	TcpHeader      *TcpHeader      `protobuf:"bytes,2,opt,name=tcp_header,json=tcpHeader,proto3" json:"tcp_header,omitempty"`
	EthernetHeader *EthernetHeader `protobuf:"bytes,3,opt,name=ethernet_header,json=ethernetHeader,proto3" json:"ethernet_header,omitempty"`
	PacketNumber   int32           `protobuf:"varint,4,opt,name=packet_number,json=packetNumber,proto3" json:"packet_number,omitempty"`
	RawData        []byte          `protobuf:"bytes,5,opt,name=raw_data,json=rawData,proto3" json:"raw_data,omitempty"`
}

func (x *UserRequest) Reset() {
	*x = UserRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_event_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserRequest) ProtoMessage() {}

func (x *UserRequest) ProtoReflect() protoreflect.Message {
	mi := &file_event_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserRequest.ProtoReflect.Descriptor instead.
func (*UserRequest) Descriptor() ([]byte, []int) {
	return file_event_proto_rawDescGZIP(), []int{3}
}

func (x *UserRequest) GetIpHeader() *IpHeader {
	if x != nil {
		return x.IpHeader
	}
	return nil
}

func (x *UserRequest) GetTcpHeader() *TcpHeader {
	if x != nil {
		return x.TcpHeader
	}
	return nil
}

func (x *UserRequest) GetEthernetHeader() *EthernetHeader {
	if x != nil {
		return x.EthernetHeader
	}
	return nil
}

func (x *UserRequest) GetPacketNumber() int32 {
	if x != nil {
		return x.PacketNumber
	}
	return 0
}

func (x *UserRequest) GetRawData() []byte {
	if x != nil {
		return x.RawData
	}
	return nil
}

type UserResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Message string `protobuf:"bytes,1,opt,name=message,proto3" json:"message,omitempty"`
}

func (x *UserResponse) Reset() {
	*x = UserResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_event_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *UserResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UserResponse) ProtoMessage() {}

func (x *UserResponse) ProtoReflect() protoreflect.Message {
	mi := &file_event_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UserResponse.ProtoReflect.Descriptor instead.
func (*UserResponse) Descriptor() ([]byte, []int) {
	return file_event_proto_rawDescGZIP(), []int{4}
}

func (x *UserResponse) GetMessage() string {
	if x != nil {
		return x.Message
	}
	return ""
}

var File_event_proto protoreflect.FileDescriptor

var file_event_proto_rawDesc = []byte{
	0x0a, 0x0b, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x04, 0x6d,
	0x61, 0x69, 0x6e, 0x22, 0x77, 0x0a, 0x0e, 0x45, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x48,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x27, 0x0a, 0x0f, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x61, 0x63, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e,
	0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x4d, 0x61, 0x63, 0x12, 0x1d,
	0x0a, 0x0a, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x5f, 0x6d, 0x61, 0x63, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x09, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x4d, 0x61, 0x63, 0x12, 0x1d, 0x0a,
	0x0a, 0x65, 0x74, 0x68, 0x65, 0x72, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x09, 0x65, 0x74, 0x68, 0x65, 0x72, 0x54, 0x79, 0x70, 0x65, 0x22, 0x89, 0x02, 0x0a,
	0x08, 0x49, 0x70, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x1b, 0x0a, 0x09, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x5f, 0x69, 0x70, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x73, 0x6f,
	0x75, 0x72, 0x63, 0x65, 0x49, 0x70, 0x12, 0x25, 0x0a, 0x0e, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d,
	0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x49, 0x70, 0x12, 0x1f, 0x0a,
	0x0b, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x68, 0x6c, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0a, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x68, 0x6c, 0x12, 0x10,
	0x0a, 0x03, 0x74, 0x6f, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x03, 0x74, 0x6f, 0x73,
	0x12, 0x17, 0x0a, 0x07, 0x74, 0x6f, 0x74, 0x5f, 0x6c, 0x65, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x06, 0x74, 0x6f, 0x74, 0x4c, 0x65, 0x6e, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x02, 0x69, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x66, 0x72, 0x61,
	0x67, 0x5f, 0x6f, 0x66, 0x66, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x66, 0x72, 0x61,
	0x67, 0x4f, 0x66, 0x66, 0x12, 0x10, 0x0a, 0x03, 0x74, 0x74, 0x6c, 0x18, 0x08, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x03, 0x74, 0x74, 0x6c, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63,
	0x6f, 0x6c, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x08, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63,
	0x6f, 0x6c, 0x12, 0x14, 0x0a, 0x05, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x18, 0x0a, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x05, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x22, 0xdd, 0x01, 0x0a, 0x09, 0x54, 0x63, 0x70,
	0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0a, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x29, 0x0a, 0x10, 0x64, 0x65, 0x73, 0x74, 0x69,
	0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x0f, 0x64, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x50, 0x6f,
	0x72, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x73, 0x65, 0x71, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52,
	0x03, 0x73, 0x65, 0x71, 0x12, 0x17, 0x0a, 0x07, 0x61, 0x63, 0x6b, 0x5f, 0x73, 0x65, 0x71, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x06, 0x61, 0x63, 0x6b, 0x53, 0x65, 0x71, 0x12, 0x12, 0x0a,
	0x04, 0x66, 0x6c, 0x61, 0x67, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x04, 0x66, 0x6c, 0x61,
	0x67, 0x12, 0x16, 0x0a, 0x06, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x06, 0x77, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x12, 0x14, 0x0a, 0x05, 0x63, 0x68, 0x65,
	0x63, 0x6b, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x63, 0x68, 0x65, 0x63, 0x6b, 0x12,
	0x17, 0x0a, 0x07, 0x75, 0x72, 0x67, 0x5f, 0x70, 0x74, 0x72, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x06, 0x75, 0x72, 0x67, 0x50, 0x74, 0x72, 0x22, 0xe9, 0x01, 0x0a, 0x0b, 0x55, 0x73, 0x65,
	0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x2b, 0x0a, 0x09, 0x69, 0x70, 0x5f, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0e, 0x2e, 0x6d, 0x61,
	0x69, 0x6e, 0x2e, 0x49, 0x70, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x08, 0x69, 0x70, 0x48,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x2e, 0x0a, 0x0a, 0x74, 0x63, 0x70, 0x5f, 0x68, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6d, 0x61, 0x69, 0x6e,
	0x2e, 0x54, 0x63, 0x70, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x52, 0x09, 0x74, 0x63, 0x70, 0x48,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x3d, 0x0a, 0x0f, 0x65, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65,
	0x74, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x14,
	0x2e, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x45, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x48, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x52, 0x0e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x6e, 0x65, 0x74, 0x48, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x12, 0x23, 0x0a, 0x0d, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x5f, 0x6e,
	0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x05, 0x52, 0x0c, 0x70, 0x61, 0x63,
	0x6b, 0x65, 0x74, 0x4e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x61, 0x77,
	0x5f, 0x64, 0x61, 0x74, 0x61, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x72, 0x61, 0x77,
	0x44, 0x61, 0x74, 0x61, 0x22, 0x28, 0x0a, 0x0c, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x18, 0x0a, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x44,
	0x0a, 0x0b, 0x55, 0x73, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x35, 0x0a,
	0x0c, 0x53, 0x65, 0x6e, 0x64, 0x55, 0x73, 0x65, 0x72, 0x44, 0x61, 0x74, 0x61, 0x12, 0x11, 0x2e,
	0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x12, 0x2e, 0x6d, 0x61, 0x69, 0x6e, 0x2e, 0x55, 0x73, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x42, 0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x69, 0x6e, 0x73, 0x70, 0x65, 0x6b, 0x74, 0x6f, 0x72, 0x73, 0x2d, 0x69, 0x6f,
	0x2f, 0x67, 0x72, 0x70, 0x63, 0x2d, 0x6e, 0x6f, 0x62, 0x69, 0x6e, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x2d, 0x74, 0x65, 0x73, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_event_proto_rawDescOnce sync.Once
	file_event_proto_rawDescData = file_event_proto_rawDesc
)

func file_event_proto_rawDescGZIP() []byte {
	file_event_proto_rawDescOnce.Do(func() {
		file_event_proto_rawDescData = protoimpl.X.CompressGZIP(file_event_proto_rawDescData)
	})
	return file_event_proto_rawDescData
}

var file_event_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_event_proto_goTypes = []interface{}{
	(*EthernetHeader)(nil), // 0: main.EthernetHeader
	(*IpHeader)(nil),       // 1: main.IpHeader
	(*TcpHeader)(nil),      // 2: main.TcpHeader
	(*UserRequest)(nil),    // 3: main.UserRequest
	(*UserResponse)(nil),   // 4: main.UserResponse
}
var file_event_proto_depIdxs = []int32{
	1, // 0: main.UserRequest.ip_header:type_name -> main.IpHeader
	2, // 1: main.UserRequest.tcp_header:type_name -> main.TcpHeader
	0, // 2: main.UserRequest.ethernet_header:type_name -> main.EthernetHeader
	3, // 3: main.UserService.SendUserData:input_type -> main.UserRequest
	4, // 4: main.UserService.SendUserData:output_type -> main.UserResponse
	4, // [4:5] is the sub-list for method output_type
	3, // [3:4] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_event_proto_init() }
func file_event_proto_init() {
	if File_event_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_event_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EthernetHeader); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_event_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IpHeader); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_event_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TcpHeader); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_event_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_event_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*UserResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_event_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_event_proto_goTypes,
		DependencyIndexes: file_event_proto_depIdxs,
		MessageInfos:      file_event_proto_msgTypes,
	}.Build()
	File_event_proto = out.File
	file_event_proto_rawDesc = nil
	file_event_proto_goTypes = nil
	file_event_proto_depIdxs = nil
}
