// Copyright (c) 2019 Dropbox, Inc.
// Full license can be found in the LICENSE file.

// TC dump is simple program that dumps new IPv4 TCP connections through perf events.

#include "../header/bpf_helpers.h"
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK (0)
#define TC_ACT_SHOT (2)
#define TC_ACT_PIPE (3)
#define TC_ACT_RECLASSIFY (1)


// Ethernet header
struct ethhdr {
  __u8 h_dest[6];
  __u8 h_source[6];
  __u16 h_proto;
} __attribute__((packed));

// IPv4 header
struct iphdr {
  __u8 ihl : 4;
  __u8 version : 4;
  __u8 tos;
  __u16 tot_len;
  __u16 id;
  __u16 frag_off;
  __u8 ttl;
  __u8 protocol;
  __u16 check;
  __u32 saddr;
  __u32 daddr;
} __attribute__((packed));

// TCP header
struct tcphdr {
  __u16 source;
  __u16 dest;
  __u32 seq;
  __u32 ack_seq;
  union {
    struct {
      // Field order has been converted LittleEndiand -> BigEndian
      // in order to simplify flag checking (no need to ntohs())
      __u16 ns : 1,
      reserved : 3,
      doff : 4,
      fin : 1,
      syn : 1,
      rst : 1,
      psh : 1,
      ack : 1,
      urg : 1,
      ece : 1,
      cwr : 1;
    };
  };
  __u16 window;
  __u16 check;
  __u16 urg_ptr;
};
__attribute__((packed));





// PerfEvent eBPF map
BPF_MAP_DEF(perfmap) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 128,
};
BPF_MAP_ADD(perfmap);

// PerfEvent item
struct perf_event_item {
    struct ethhdr eth_hdr;
    struct iphdr ip_hdr;
    // __u16 source;
    // __u16 dest;
    // __u32 seq;
    // __u32 ack_seq; 
    struct tcphdr tcp_hdr;
} __attribute__((packed));

_Static_assert(sizeof(struct perf_event_item) == 54, "wrong size of perf_event_item");


// TC program
SEC("tc")
int tc_dump(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;
  __u64 packet_size = data_end - data;

  // L2
  struct ethhdr *ether = data;
  if (data + sizeof(*ether) > data_end) {
    return TC_ACT_SHOT;
  }

  // L3
  if (ether->h_proto != 0x08) {  // htons(ETH_P_IP) -> 0x08
    // Non IPv4
    return TC_ACT_OK;
  }
  data += sizeof(*ether);
  struct iphdr *ip = data;
  if (data + sizeof(*ip) > data_end) {
    return TC_ACT_SHOT;
  }

  data += ip->ihl * 4;
  struct tcphdr *tcp = data;
  if (data + sizeof(*tcp) > data_end) {
    return TC_ACT_SHOT;
  }

  // Emit perf event for every ICMP packet
  if (ip->protocol) {  // IPPROTO_TCP -> 6
    struct perf_event_item evt = {
      .eth_hdr = *ether,
      .ip_hdr = *ip,
      .tcp_hdr = *tcp,
      // .src_ip = ip->saddr,
      // .dst_ip = ip->daddr,
      // .source = tcp->source,
      // .dest = tcp->dest,
      // .seq = tcp->seq,
      // .ack_seq = tcp->ack_seq,
    };

    // flags for bpf_perf_event_output() actually contain 2 parts (each 32bit long):
    //
    // bits 0-31: either
    // - Just index in eBPF map
    // or
    // - "BPF_F_CURRENT_CPU" kernel will use current CPU_ID as eBPF map index
    //
    // bits 32-63: may be used to tell kernel to amend first N bytes
    // of original packet (ctx) to the end of the data.

    // So total perf event length will be sizeof(evt) + packet_size
    __u64 flags = BPF_F_CURRENT_CPU | (packet_size << 32);
    bpf_perf_event_output(skb, &perfmap, flags, &evt, sizeof(evt));
  }

  return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";