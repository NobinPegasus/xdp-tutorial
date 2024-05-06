#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include "include/ip.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include "include/helpers.h"
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/net.h>


#include <linux/ip.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define ETH_P_IP 0x0800 /* Internet Protocol Packet */
#define PROTO_TCP 6
#define PROTO_UDP 17

struct packetdets {
    __u32 source;
    __u16 source_port;
    __u32 dest;
    __u16 dest_port;
    __u8 ip_protocol;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct packetdets);
    __type(value, __u64);
    __uint(max_entries, 1000);
} pkt_count SEC(".maps");


SEC("tc_prog")
int tc_main(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    __u32 *value;

    eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    ip = data + 0;
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    __u32 source = bpf_ntohl(ip->saddr);
    __u32 dest = bpf_ntohl(ip->daddr);

    if (dest == 3116855193){
        return TC_ACT_SHOT;
    }

    __u16 source_port;
    __u16 dest_port;
    __u8 ip_proto;
    if (ip->protocol == PROTO_TCP) {
        tcp = (void *)ip + ip->ihl*4;
        if ((void *)tcp + sizeof(struct tcphdr) > data_end) {
            return TC_ACT_OK;
        }
        source_port = tcp->source;
        dest_port = tcp->dest;
        ip_proto = PROTO_TCP;
    } else if (ip->protocol == PROTO_UDP) {
        udp = (void *)ip + ip->ihl*4;
        if ((void *)udp + sizeof(struct udphdr) > data_end) {
            return TC_ACT_OK;
        }
        source_port = udp->source;
        dest_port = udp->dest;
        ip_proto = PROTO_UDP;
    } else {
        return TC_ACT_OK;
    }

    // Update packet count map
    struct packetdets key = {
        .source = source,
        .source_port = source_port,
        .dest = dest,
        .dest_port = dest_port,
        .ip_protocol = ip_proto,
    };
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 value = 1;
        bpf_map_update_elem(&pkt_count, &key, &value, BPF_ANY);
    }

    char hello_str[] = "hello pkt ipv4: %u";
    bpf_trace_printk(hello_str, sizeof(hello_str), &skb->remote_ip4);
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";

