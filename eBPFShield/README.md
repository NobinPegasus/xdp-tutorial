### Workflow diagram

![eBPFShield.drawio (1).png](https://prod-files-secure.s3.us-west-2.amazonaws.com/f4ef8738-892f-41b5-9c2c-e3f847edae14/3f54a9ca-5761-4d82-b844-7e80092b1dce/eBPFShield.drawio_(1).png)

### Proof of Concept(PoC)

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/f4ef8738-892f-41b5-9c2c-e3f847edae14/302adf1e-db72-4a3a-944d-be1227008488/Untitled.png)

### Commands to run this tools

Install the prerequisites:

`sudo apt install python3-bpfcc bpfcc-tools libbpfcc linux-headers-$(uname -r)`

If there’s any error:

Install BCC from it’s official repo.

```python
git clone https://github.com/sagarbhure/eBPFShield.git
cd eBPFShield
./update_feeds.sh
sudo rm ip_feeds/web_crawler.txt

// edit the txt files to remove all blank lines at the end of the files
python3 main.py  --feature ebpf_ipintelligence --block kill

//open another terminal, use curl
curl -v google.com
curl -v 114.91.196.176
```

### Explanations

From `[main.py](http://main.py)` we are importing TaggedIpList.

```bash
from ebpfshield.helpers import TaggedIpList
```

Here we are reading the handle and reading it line by line. We are skipping the commented lines that start with `#`. Otherwise, we are converting the string IPv4 formatted addresses into integers and appending them to the list named addresses. Finally, we are sorting the addresses, stored into the list.

```bash
class TaggedIpList:
    def __init__(self, tag, handle):
        self.addresses = []
        self.tag = tag
        for line in handle:
            line = line.strip()

            if line and line[0] == "#":
                continue

            self.addresses.append(self.ip2int(line))

        self.addresses = sorted(self.addresses)
```

The provided **`C_BPF_KPROBE`** string defines a C language script for an eBPF.

The eBPF code:

```bash
C_BPF_KPROBE = """
#include <net/sock.h>
//the structure that will be used as a key for
// eBPF table 'proc_ports':
struct port_key {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
// the structure which will be stored in the eBPF table 'proc_ports',
// contains information about the process:
struct port_val {
    u32 ifindex;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[64];
};
// Public (accessible from other eBPF programs) eBPF table
// information about the process is written to.
// It is read when a packet appears on the socket:
BPF_TABLE_PUBLIC("hash", struct port_key, struct port_val, proc_ports, 20480);
int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    // Processing only packets on port 53.
    // 13568 = ntohs(53);
    if (sport == 13568 || dport == 13568) {
        // Preparing the data:
        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = 17};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);
        //Forming a structure with socket properties:
        struct port_val val = {};
        val.pid = pid_tgid >> 32;
        val.tgid = (u32)pid_tgid;
        val.uid = (u32)uid_gid;
        val.gid = uid_gid >> 32;
        bpf_get_current_comm(val.comm, 64);
        //Write the value into the eBPF table:
        proc_ports.update(&key, &val);
    }
    return 0;
}
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    // Processing only packets on port 53.
    // 13568 = ntohs(53);
    if (sport == 13568 || dport == 13568) {
        // preparing the data:
        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = 6};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);
        //Form a structure with socket properties:
        struct port_val val = {};
        val.pid = pid_tgid >> 32;
        val.tgid = (u32)pid_tgid;
        val.uid = (u32)uid_gid;
        val.gid = uid_gid >> 32;
        bpf_get_current_comm(val.comm, 64);
        //Write the value into the eBPF table:
        proc_ports.update(&key, &val);
    }
    return 0;
}
"""
```

We define `BPF_TABLE_PUBLIC("hash", struct port_key, struct port_val, proc_ports, 20480);` a bpf map here. With port_key as key and port_val as value. It is a hash tybe bpf map. And we name it proc_ports and it’s size is 20480. 

The key struct has protocol, source address and ports destination address and ports fields.

```bash
struct port_key {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
```

The value struct has: interface index, process id, group id, user id, thread group id and an command name array.

```bash
struct port_val {
    u32 ifindex;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[64];
};
```

This function are meant to be attached to the UDP and TCP **`sendmsg`** system calls (or equivalent kernel functions). They are triggered every time a **`sendmsg`** operation is executed by a process. The functions filter for packets sent or received on port 53, which is standard for DNS communication. They then log relevant process and network data into the **`proc_ports`** eBPF table.

```bash
int trace_udp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    // Processing only packets on port 53.
    // 13568 = ntohs(53);
    if (sport == 13568 || dport == 13568) {
        // Preparing the data:
        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = 17};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);
        //Forming a structure with socket properties:
        struct port_val val = {};
        val.pid = pid_tgid >> 32;
        val.tgid = (u32)pid_tgid;
        val.uid = (u32)uid_gid;
        val.gid = uid_gid >> 32;
        bpf_get_current_comm(val.comm, 64);
        //Write the value into the eBPF table:
        proc_ports.update(&key, &val);
    }
    return 0;
}
```

It gets triggered during sendmsg syscall. It retrieves socket information (sk) from the function context. It then captures the source and destination ports. It only processes the packets on port 53, which is the default port for DNS. It then populates the key and value structs with relevant values. The udp protocol is 17. `val.gid = uid_gid >> 32;` means `uid_gid` is a 64 bit value. Only the upper 32 bits are group id.

1. **`htonl` (Host TO Network Long):**
    - Converts a 32-bit (long) integer from host byte order to network byte order.
    - **`u32`** implies that it works with an unsigned 32-bit integer.
2. **`htons` (Host TO Network Short):**
    - Converts a 16-bit (short) integer from host byte order to network byte order.
    - **`u16`** indicates that it works with an unsigned 16-bit integer.

By calling **`bpf_get_current_comm`**, the eBPF program can store the name of the current process directly into the **`val.comm`** field, and the later argument defines the size.

Finally, entry the eBPF map with the populated key and value structs.

The following code does the same thing, as the above one except it gets triggered for tcp packets. And the protocol number of tcp is 6.

```bash
int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
  
    // Processing only packets on port 53.
    // 13568 = ntohs(53);
    if (sport == 13568 || dport == 13568) {
        // preparing the data:
        u32 saddr = sk->sk_rcv_saddr;
        u32 daddr = sk->sk_daddr;
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the structure-key.
        struct port_key key = {.proto = 6};
        key.saddr = htonl(saddr);
        key.daddr = htonl(daddr);
        key.sport = sport;
        key.dport = htons(dport);
        //Form a structure with socket properties:
        struct port_val val = {};
        val.pid = pid_tgid >> 32;
        val.tgid = (u32)pid_tgid;
        val.uid = (u32)uid_gid;
        val.gid = uid_gid >> 32;
        bpf_get_current_comm(val.comm, 64);
        //Write the value into the eBPF table:
        proc_ports.update(&key, &val);
    }
    return 0;
}
```

## Extracted to User Space

Our second program is **BPF_SOCK_TEXT**
It will “hang” on the socket, will check for information about the 
corresponding process for each packet and transmit it, along with the 
packet itself, to user space:

The **`BPF_SOCK_TEXT`** string in your example contains a C language eBPF program intended for use with the BCC (BPF Compiler Collection) toolset. This eBPF program is designed to monitor and analyze DNS traffic directly from packet data as it traverses network interfaces. 

```bash
BPF_SOCK_TEXT = r'''
#include <net/sock.h>
#include <bcc/proto.h>

//the structure that will be used as a key for
// eBPF table 'proc_ports':
struct port_key {
    u8 proto;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
};
// the structure which will be stored in the eBPF table 'proc_ports',
// contains information about the process:
struct port_val {
    u32 ifindex;
    u32 pid;
    u32 tgid;
    u32 uid;
    u32 gid;
    char comm[64];
};
// eBPF table from which information about the process is extracted.
// Filled when calling kernel functions udp_sendmsg()/tcp_sendmsg():

BPF_TABLE("extern", struct port_key, struct port_val, proc_ports, 20480);
// table for transmitting data to the user space:

BPF_PERF_OUTPUT(dns_events);
// Among the data passing through the socket, look for DNS packets
// and check for information about the process:

int dns_matching(struct __sk_buff *skb) {
    u8 *cursor = 0;
    // check the IP protocol:
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    
    if (ethernet->type == ETH_P_IP) {
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        u8 proto;
        u16 sport;
        u16 dport;
        // We check the transport layer protocol:
        if (ip->nextp == IPPROTO_UDP) {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
            proto = 17;
            //receive port data:
            sport = udp->sport;
            dport = udp->dport;
        } else if (ip->nextp == IPPROTO_TCP) {
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
            // We don't need packets where no data is transmitted:
            if (!tcp->flag_psh) {
                return 0;
            }
            proto = 6;
            // We get the port data:
            sport = tcp->src_port;
            dport = tcp->dst_port;
        } else {
            return 0;
        }
        // if this is a DNS request:
        if (dport == 53 || sport == 53) {
            // we form the structure-key:
            struct port_key key = {};
            key.proto = proto;
            if (skb->ingress_ifindex == 0) {
                key.saddr = ip->src;
                key.daddr = ip->dst;
                key.sport = sport;
                key.dport = dport;
            } else {
                key.saddr = ip->dst;
                key.daddr = ip->src;
                key.sport = dport;
                key.dport = sport;
            }
            // By the key we are looking for a value in the eBPF table:
            struct port_val *p_val;
            p_val = proc_ports.lookup(&key);
            // If the value is not found, it means that we do not have information about the
            // process, so there is no point in continuing:
            if (!p_val) {
                return 0;
            }
            // network device index:
            p_val->ifindex = skb->ifindex;
            // pass the structure with the process information along with
            // skb->len bytes sent to the socket:
            dns_events.perf_submit_skb(skb, skb->len, p_val,
                                       sizeof(struct port_val));
            return 0;
        } //dport == 53 || sport == 53
    } //ethernet->type == ETH_P_IP
    return 0;
}
'''
```

The key and value struct are the same as `C_BPF_KPROBE`.

```bash
BPF_TABLE("extern", struct port_key, struct port_val, proc_ports, 20480);
// table for transmitting data to the user space:

BPF_PERF_OUTPUT(dns_events);
// Among the data passing through the socket, look for DNS packets
// and check for information about the process:
```

A macro that ***[cursor_advance](https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h#L524)*** moves the cursor (pointer) around the packet, returning its current 
position and shifting it by the specified amount, will help us do this:

```
BPF_TABLE_PUBLIC("hash", key, val, name, max_elements);
```

The `extern` keyword used is to make it available to other eBPF programs. And to access it, in another program, we write like this:

```
BPF_TABLE("extern", key, val, name, max_elements);
```

The following code defines a performance event array to push data to user-space, specifically formatted data about DNS requests and responses. Among the data that passes through the socket, it looks for DNS packets and checks for information about the process.

- BPF_PERF_OUTPUT
    
    Syntax: `BPF_PERF_OUTPUT(name)`
    
    Creates a BPF table for pushing out custom event data to user space via a perf 
    ring buffer. This is the preferred method for pushing per-event data to 
    user space.
    

```bash
BPF_PERF_OUTPUT(dns_events);
```

The following is the dns_matching function, used for parsing the packets, to catch TCP/UDP with port 53 among all the packets. And to do this, we will have to disassemble the package structure ourselves and separate all the nested protocols, starting with Ethernet. A macro that ***[cursor_advance](https://github.com/iovisor/bcc/blob/master/src/cc/export/helpers.h#L524)*** moves the cursor (pointer) around the packet, returning its current position and shifting it by the specified amount. We then check if it’s an IP protocol. If it’s IP protocol we check for the transport layer protocols namely, TCP/UDP and parse it accordingly populate the respective fields (`**sport, dport**`) accordingly. We then check if it uses port 53 as source or destination, which denotes it’s a DNS Request. If it’s a DNS request we populate the source, destination ip and ports. Then we look for the particular entry using key in eBPF map. If the value is not found, it means that we do not have information about the process, so there is no point in continuing, so we return.

```bash
int dns_matching(struct __sk_buff *skb) {
    u8 *cursor = 0;
    // check the IP protocol:
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    
    if (ethernet->type == ETH_P_IP) {
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
        u8 proto;
        u16 sport;
        u16 dport;
        // We check the transport layer protocol:
        if (ip->nextp == IPPROTO_UDP) {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));
            proto = 17;
            //receive port data:
            sport = udp->sport;
            dport = udp->dport;
        } else if (ip->nextp == IPPROTO_TCP) {
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
            // We don't need packets where no data is transmitted:
            if (!tcp->flag_psh) {
                return 0;
            }
            proto = 6;
            // We get the port data:
            sport = tcp->src_port;
            dport = tcp->dst_port;
        } else {
            return 0;
        }
        // if this is a DNS request:
        if (dport == 53 || sport == 53) {
            // we form the structure-key:
            struct port_key key = {};
            key.proto = proto;
            if (skb->ingress_ifindex == 0) {
                key.saddr = ip->src;
                key.daddr = ip->dst;
                key.sport = sport;
                key.dport = dport;
            } else {
                key.saddr = ip->dst;
                key.daddr = ip->src;
                key.sport = dport;
                key.dport = sport;
            }
            // By the key we are looking for a value in the eBPF table:
            struct port_val *p_val;
            p_val = proc_ports.lookup(&key);
            // If the value is not found, it means that we do not have information about the
            // process, so there is no point in continuing:
            if (!p_val) {
                return 0;
            }
            // network device index:
            p_val->ifindex = skb->ifindex;
            // pass the structure with the process information along with
            // skb->len bytes sent to the socket:
            dns_events.perf_submit_skb(skb, skb->len, p_val,
                                       sizeof(struct port_val));
            return 0;
        } //dport == 53 || sport == 53
    } //ethernet->type == ETH_P_IP
    return 0;
}
```

- perf_submit_skb()
    
    Syntax: `int perf_submit_skb((void *)ctx, u32 packet_size, (void *)data, u32 data_size)`
    
    Return: 0 on success
    
    A method of a BPF_PERF_OUTPUT table available in networking program 
    types, for submitting custom event data to user space, along with the 
    first `packet_size` bytes of the packet buffer. See the BPF_PERF_OUTPUT entry. (This ultimately calls bpf_perf_event_output().)
    

## Serving

From Python, we need three things: load our programs into the kernel, get data from them, and process it.

The total code:

```bash
def print_dns(cpu, data, size):
    import ctypes as ct
    class SkbEvent(ct.Structure):
        _fields_ = [
            ("ifindex", ct.c_uint32),
            ("pid", ct.c_uint32),
            ("tgid", ct.c_uint32),
            ("uid", ct.c_uint32),
            ("gid", ct.c_uint32),
            ("comm", ct.c_char * 64),
            ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32 * 5) - ct.sizeof(ct.c_char * 64)))
        ]
    # We get our 'port_val' structure and also the packet itself in the 'raw' field:
    sk = ct.cast(data, ct.POINTER(SkbEvent)).contents

    # Protocols:
    NET_PROTO = {6: "TCP", 17: "UDP"}

    # eBPF operates on thread names.
    # Sometimes they are the same as the process names, but often they are not.
    # So we try to get the process name by its PID:
    try:
        with open(f'/proc/{sk.pid}/comm', 'r') as proc_comm:

            proc_name = proc_comm.read().rstrip()
    except:
        proc_name = sk.comm.decode()

    # Get the name of the network interface by index:
    ifname = if_indextoname(sk.ifindex)

    # The length of the Ethernet frame header is 14 bytes:
    ip_packet = bytes(sk.raw[14:])

    # The length of the IP packet header is not fixed due to the arbitrary
    # number of parameters.
    # Of all the possible IP header we are only interested in 20 bytes:
    (length, _, _, _, _, proto, _, saddr, daddr) = unpack('!BBHLBBHLL', ip_packet[:20])
    # The direct length is written in the second half of the first byte (0b00001111 = 15):
    len_iph = length & 15
    # Length is written in 32-bit words, convert it to bytes:
    len_iph = len_iph * 4
    # Convert addresses from numbers to IPs:
    saddr = ".".join(map(str, [saddr >> 24 & 0xff, saddr >> 16 & 0xff, saddr >> 8 & 0xff, saddr & 0xff]))
    daddr = ".".join(map(str, [daddr >> 24 & 0xff, daddr >> 16 & 0xff, daddr >> 8 & 0xff, daddr & 0xff]))

    # If the transport layer protocol is UDP:
    if proto == 17:
        udp_packet = ip_packet[len_iph:]
        (sport, dport) = unpack('!HH', udp_packet[:4])
        # UDP datagram header length is 8 bytes:
        dns_packet = udp_packet[8:]
    # If the transport layer protocol is TCP:
    elif proto == 6:
        tcp_packet = ip_packet[len_iph:]
        # The length of the TCP packet header is also not fixed due to the optional options.
        # Of the entire TCP header we are only interested in the data up to the 13th byte
        # (header length):
        (sport, dport, _, length) = unpack('!HHQB', tcp_packet[:13])
        # The direct length is written in the first half (4 bits):
        len_tcph = length >> 4
        # Length is written in 32-bit words, converted to bytes:
        len_tcph = len_tcph * 4
        # That's the tricky part.
        # I don't know where I went wrong or why I need a 2 byte offset,
        # but it's necessary because the DNS packet doesn't start until after it:
        dns_packet = tcp_packet[len_tcph + 2:]
    # other protocols are not handled:
    else:
        return

    # DNS data decoding:
    dns_data = dnslib.DNSRecord.parse(dns_packet)

    # Resource record types:
    DNS_QTYPE = {1: "A", 28: "AAAA"}

    # Query:
    if dns_data.header.qr == 0:
        # We are only interested in A (1) and AAAA (28) records:
        for q in dns_data.questions:
            if q.qtype == 1 or q.qtype == 28:
                print(f'COMM={proc_name} PID={sk.pid} TGID={sk.tgid} DEV={ifname} PROTO={NET_PROTO[proto]} SRC={saddr} DST={daddr} SPT={sport} DPT={dport} UID={sk.uid} GID={sk.gid} DNS_QR=0 DNS_NAME={q.qname} DNS_TYPE={DNS_QTYPE[q.qtype]}')
    # Response:
    elif dns_data.header.qr == 1:
        # We are only interested in A (1) and AAAA (28) records:
        for rr in dns_data.rr:
            if rr.rtype == 1 or rr.rtype == 28:
                print(f'COMM={proc_name} PID={sk.pid} TGID={sk.tgid} DEV={ifname} PROTO={NET_PROTO[proto]} SRC={saddr} DST={daddr} SPT={sport} DPT={dport} UID={sk.uid} GID={sk.gid} DNS_QR=1 DNS_NAME={rr.rname} DNS_TYPE={DNS_QTYPE[rr.rtype]} DNS_DATA={rr.rdata}')
    else:
        print('Invalid DNS query type.')
```

The ctypes is let us use c type of data types in python. We define a c type struct named SkbEvent with the fields: `**"ifindex", "pid", "tgid", "uid", "gid", "comm", "raw"**` with ctype datatypes. This structure will be used to read `**port_val**` from eBPF map. The `**ct.cast**` converts data to a pointer of type `**SkbEvent**`. Finally, **`.contents`** accesses the actual data that the pointer points to, allowing you to work with the data as if it were a **`SkbEvent`** object.

```bash
def print_dns(cpu, data, size):
    import ctypes as ct
    class SkbEvent(ct.Structure):
        _fields_ = [
            ("ifindex", ct.c_uint32),
            ("pid", ct.c_uint32),
            ("tgid", ct.c_uint32),
            ("uid", ct.c_uint32),
            ("gid", ct.c_uint32),
            ("comm", ct.c_char * 64),
            ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32 * 5) - ct.sizeof(ct.c_char * 64)))
        ]
    # We get our 'port_val' structure and also the packet itself in the 'raw' field:
    sk = ct.cast(data, ct.POINTER(SkbEvent)).contents
```

Then we take the dictionaries of the protocols we are going to work on.

```bash
    # Protocols:
    NET_PROTO = {6: "TCP", 17: "UDP"}
```

We try to get the process name by it’s PID. Then we get the interface index.

```bash
    try:
        with open(f'/proc/{sk.pid}/comm', 'r') as proc_comm:

            proc_name = proc_comm.read().rstrip()
    except:
        proc_name = sk.comm.decode()
 
	  # Get the name of the network interface by index:
    ifname = if_indextoname(sk.ifindex) 
```

Since the first 14 bytes are ethernet bytes. It starts reading after the 14 bytes.

```python
    # The length of the Ethernet frame header is 14 bytes:
    ip_packet = bytes(sk.raw[14:])

    # The length of the IP packet header is not fixed due to the arbitrary
    # number of parameters.
    # Of all the possible IP header we are only interested in 20 bytes:
    (length, _, _, _, _, proto, _, saddr, daddr) = unpack('!BBHLBBHLL', ip_packet[:20])
    # The direct length is written in the second half of the first byte (0b00001111 = 15):
    len_iph = length & 15
    # Length is written in 32-bit words, convert it to bytes:
    len_iph = len_iph * 4
    # Convert addresses from numbers to IPs:
    saddr = ".".join(map(str, [saddr >> 24 & 0xff, saddr >> 16 & 0xff, saddr >> 8 & 0xff, saddr & 0xff]))
    daddr = ".".join(map(str, [daddr >> 24 & 0xff, daddr >> 16 & 0xff, daddr >> 8 & 0xff, daddr & 0xff]))
```

The **`unpack`** function is used here with the format string **`!BBHLBBHLL`**, which corresponds to the structure of the first 20 bytes of an IP header:

- **`!`** - network byte order (big-endian)
- **`B`** - one byte (8 bits) for the first part of the header (Version and IHL)
- **`B`** - one byte for type of service (ToS)
- **`H`** - two bytes for total length
- **`L`** - four bytes for identification, flags, and fragment offset
- **`B`** - one byte for time to live (TTL)
- **`B`** - one byte for protocol
- **`H`** - two bytes for header checksum
- **`L`** - four bytes for source IP address
- **`L`** - four bytes for destination IP address

We capture only the length, proto, saddr, daddr.

The IP header length (**`IHL`** - Internet Header Length) is stored in the lower 4 bits of the first byte (**`length`**). The IHL tells how many 32-bit words the header consists of. By masking the first byte with **`15`** (binary **`1111`**), you isolate these lower 4 bits. Multiplying this result by 4 converts the count of 32-bit words into bytes

The following lines converts 32 bits address to IPv4 dotted notation.

```bash
    # Convert addresses from numbers to IPs:
    saddr = ".".join(map(str, [saddr >> 24 & 0xff, saddr >> 16 & 0xff, saddr >> 8 & 0xff, saddr & 0xff]))
    daddr = ".".join(map(str, [daddr >> 24 & 0xff, daddr >> 16 & 0xff, daddr >> 8 & 0xff, daddr & 0xff]))
```

The following code snippet parses the udp/tcp packets based on the protocols. And populates the sport, dport

```python
    # If the transport layer protocol is UDP:
    if proto == 17:
        udp_packet = ip_packet[len_iph:]
        (sport, dport) = unpack('!HH', udp_packet[:4])
        # UDP datagram header length is 8 bytes:
        dns_packet = udp_packet[8:]
    # If the transport layer protocol is TCP:
    elif proto == 6:
        tcp_packet = ip_packet[len_iph:]
        # The length of the TCP packet header is also not fixed due to the optional options.
        # Of the entire TCP header we are only interested in the data up to the 13th byte
        # (header length):
        (sport, dport, _, length) = unpack('!HHQB', tcp_packet[:13])
        # The direct length is written in the first half (4 bits):
        len_tcph = length >> 4
        # Length is written in 32-bit words, converted to bytes:
        len_tcph = len_tcph * 4
        # That's the tricky part.
        # I don't know where I went wrong or why I need a 2 byte offset,
        # but it's necessary because the DNS packet doesn't start until after it:
        dns_packet = tcp_packet[len_tcph + 2:]
    # other protocols are not handled:
    else:
        return
```

The unpack is formatted as the following:

- **`H`**: Unsigned short (2 bytes)
- **`H`**: Unsigned short (2 bytes)
- **`Q`**: Unsigned long long (8 bytes)
- **`B`**: Unsigned char (1 byte)

The following snippet parses the dns_packet in using dnslib library. If the query or the response is of A or AAAA type it prints the relevant information.

```python
    # DNS data decoding:
    dns_data = dnslib.DNSRecord.parse(dns_packet)

    # Resource record types:
    DNS_QTYPE = {1: "A", 28: "AAAA"}

    # Query:
    if dns_data.header.qr == 0:
        # We are only interested in A (1) and AAAA (28) records:
        for q in dns_data.questions:
            if q.qtype == 1 or q.qtype == 28:
                print(f'COMM={proc_name} PID={sk.pid} TGID={sk.tgid} DEV={ifname} PROTO={NET_PROTO[proto]} SRC={saddr} DST={daddr} SPT={sport} DPT={dport} UID={sk.uid} GID={sk.gid} DNS_QR=0 DNS_NAME={q.qname} DNS_TYPE={DNS_QTYPE[q.qtype]}')
    # Response:
    elif dns_data.header.qr == 1:
        # We are only interested in A (1) and AAAA (28) records:
        for rr in dns_data.rr:
            if rr.rtype == 1 or rr.rtype == 28:
                print(f'COMM={proc_name} PID={sk.pid} TGID={sk.tgid} DEV={ifname} PROTO={NET_PROTO[proto]} SRC={saddr} DST={daddr} SPT={sport} DPT={dport} UID={sk.uid} GID={sk.gid} DNS_QR=1 DNS_NAME={rr.rname} DNS_TYPE={DNS_QTYPE[rr.rtype]} DNS_DATA={rr.rdata}')
    else:
        print('Invalid DNS query type.')
```

### process_netevent

```python
def process_netevent(cpu, data, size):
    global lists
    global args
    event = bpf_sock["events"].event(data)
    ip_address = socket.inet_ntoa(struct.pack("I", event.address))
    ip_port = socket.inet_ntoa(struct.pack("I", event.port))
#   ip_comm = socket.inet_ntoa(struct.pack("I", event.comm))

    if args.verbose:
        printb(b"\t%s (%d) %s:%d" % (
            event.comm, event.pid, ip_address, socket.htons(event.port)
        ))

    for feed in lists:
        if feed.check_membership(ip_address):
            if args.block == "print":
                print("Client:{} (pid:{}) touched a bad IP (ip-blacklist:{})".format(
                    event.comm, event.pid, ip_address
                ))
            elif args.block == "dump":
                os.kill(event.pid, 19)
                os.system("gcore -o /tmp/ebpfshield-{}.core {} 2>/dev/null".format(event.ts, event.pid))
                os.kill(event.pid, 9)
                print("Client:{} (pid:{}) eBPFShield took a dump in /tmp/ (ip-blacklist:{})".format(
                    event.comm, event.pid, ip_address
                ))
            elif args.block == "suspend":
                os.kill(event.pid, 19)
                print("Client:{} (pid:{}) was suspended (ip-blacklist:{}) ".format(
                    event.comm, event.pid, ip_address
                ))
            elif args.block == "kill":
                os.kill(event.pid, 9)
                print("Client:{} (pid:{}) was killed by eBPFShield (ip-blacklist:{}) ".format(
                    event.comm, event.pid, ip_address
                ))
```

It is used to read data from eBPF map

```python
event = bpf_sock["events"].event(data)
```

`**ip_address = socket.inet_ntoa(struct.pack("I", event.address))**` 

Here **`event.address`** as an unsigned integer (32-bit) using the native endianness of the machine is converted into a human readable IPv4 dot notation.

In the same way `**ip_port**` is also converted.

If the `**--verbose**` flag is used it prints command, pid, address and port read from the eBPF map.

```python
    if args.verbose:
        printb(b"\t%s (%d) %s:%d" % (
            event.comm, event.pid, ip_address, socket.htons(event.port)
        ))
```

This portion reads from list and checks where the ip is present in the ip list or not.

Then based on the option passed with the `**--block**` flag it takes actions:

- `**print**` it just prints the blocklistes ip, pid and command
- `**dump**` The `**os.kill(event.pid, 19)**` pauses the process execution. **`gcore`**, a utility that generates a core dump of a running process. A core dump is essentially a snapshot of a process's memory and state at a specific point in time, useful for debugging and forensic analysis. The `**os.kill(event.pid, 9)**` is equivalent to **`SIGKILL`**. This signal forcibly terminates the process and cannot be caught or ignored, ensuring that the process is stopped completely.
- `**suspend**` The `**os.kill(event.pid, 19)**` pauses the process execution.
- `**kill**` The `**os.kill(event.pid, 9)**` pauses the kills execution.

```python
    for feed in lists:
        if feed.check_membership(ip_address):
            if args.block == "print":
                print("Client:{} (pid:{}) touched a bad IP (ip-blacklist:{})".format(
                    event.comm, event.pid, ip_address
                ))
            elif args.block == "dump":
                os.kill(event.pid, 19)
                os.system("gcore -o /tmp/ebpfshield-{}.core {} 2>/dev/null".format(event.ts, event.pid))
                os.kill(event.pid, 9)
                print("Client:{} (pid:{}) eBPFShield took a dump in /tmp/ (ip-blacklist:{})".format(
                    event.comm, event.pid, ip_address
                ))
            elif args.block == "suspend":
                os.kill(event.pid, 19)
                print("Client:{} (pid:{}) was suspended (ip-blacklist:{}) ".format(
                    event.comm, event.pid, ip_address
                ))
            elif args.block == "kill":
                os.kill(event.pid, 9)
                print("Client:{} (pid:{}) was killed by eBPFShield (ip-blacklist:{}) ".format(
                    event.comm, event.pid, ip_address
                ))
```

- **check_membership function**
    
    It is defined inside [helpers.py](http://helpers.py) file:
    
    ```python
        def check_membership(self, ip_address):
            ip_address = self.ip2int(ip_address)
    
            low = 0
            high = len(self.addresses)-1
    
            while high >= low:
                midpoint = (low + high)//2
                if self.addresses[midpoint] == ip_address:
                    return True
                elif self.addresses[midpoint] > ip_address:
                    high = midpoint-1
                elif self.addresses[midpoint] < ip_address:
                    low = midpoint+1
    
            return False
    ```
    
    This function does a binary search inside the lists, returns true when the given ip is present inside the sorted Ip address’ list.
    

ArgumentParser snippet:

```python
parser = argparse.ArgumentParser()
parser.add_argument("--block", default="print", choices=["print", "dump", "suspend", "kill"])
parser.add_argument("--feature", default="ebpf_ipintelligence", choices=["ebpf_ipintelligence", "ebpf_monitor"])
parser.add_argument("--verbose", action="store_true")
argcomplete.autocomplete(parser)

args = parser.parse_args()
```

This code initializes **`ArgumentParser`** object, which will be used to handle command-line arguments. In each flag it has different options, those are defined. The **`argcomplete`** is a third-party library, to provide command-line autocompletion for the arguments defined in **`parser`**. The parsed arguments are then accessible as attributes of the **`args`** object. For instance, **`args.block`**, **`args.feature`**, and **`args.verbose`** would hold the values provided by the user or their respective defaults.

The following code snippet is used to read the blocklist of ip addresses which are present inside the `ip_feeds` directory. Each file is read and each ip inside the files are appended to the list. The ip addresses are converted into the integer type.

```python
outs = glob.glob("ip_feeds/*.txt")
lists = []
if outs:
    for feed in outs:
        with open(feed, 'r') as handle:
            lists.append(TaggedIpList(feed, handle))
else:
    raise ValueError("No feeds available. Run update_feeds.sh!")
```

If we pass `ebpf_ipintelligence` with `--feature` flag, the following snippet will be executed.

```python
if args.feature == "ebpf_ipintelligence":
    bpf_sock = BPF(src_file="ebpfshield.c")
    #bpf_sock.attach_kprobe(event=b.get_syscall_fnname("connect"), fn_name="probe_connect_enter")
    bpf_sock.attach_kprobe(event="tcp_v4_connect", fn_name="tcp_v4")
    #bpf_sock.attach_kprobe(event="udp_sendmsg", fn_name="udp_v4")
    print('The program is running. Press Ctrl-C to abort.')
    bpf_sock["events"].open_perf_buffer(process_netevent)
```

First a **`BPF`** object is created using the BCC (BPF Compiler Collection) framework using the ebpfshield.c code. Then we attach the `tcp_v4_connect` kernel function with `tcp_v4` defined inside the `ebpfshield.c` file.

- tcp_v4 function
    
    ### **Function Signature**
    
    ```c
    int tcp_v4(struct pt_regs *ctx, struct sock *sk, struct sockaddr *uaddr, int addr_len)
    ```
    
    - **`struct pt_regs *ctx`**: A pointer to CPU registers, providing context about the system state when the function is invoked.
    - **`struct sock *sk`**: A pointer to a **`sock`** structure, representing the socket data structure in the kernel.
    - **`struct sockaddr *uaddr`**: A pointer to a **`sockaddr`** structure, representing the network address to which the socket is trying to connect.
    - **`int addr_len`**: The length of the address structure.
    
    ### **Address Validation**
    
    ```c
    struct sockaddr_in* poop = (struct sockaddr_in*) uaddr;
    if (poop->sin_family != AF_INET) {
        return 0;
    }
    ```
    
    - **Cast `sockaddr` to `sockaddr_in`**: The generic **`sockaddr`** structure is cast to **`sockaddr_in`**, which is used specifically for handling IPv4 addresses.
    - **Check Address Family**: Validates that the address family is indeed **`AF_INET`** (IPv4). If not, the function exits early by returning **`0`**.
    
    ### **Prepare Network Event Data**
    
    ```c
    struct netevent_t netevent = {};
    netevent.pid = bpf_get_current_pid_tgid();
    netevent.ts = bpf_ktime_get_ns();
    netevent.fd = sk->__sk_common.skc_family;
    netevent.uid = bpf_get_current_uid_gid();
    netevent.port = poop->sin_port;
    netevent.address = poop->sin_addr.s_addr;
    bpf_get_current_comm(&netevent.comm, sizeof(netevent.comm));
    ```
    
    - **`struct netevent_t netevent`**: Initializes a struct to hold data about the network event.
    - **Current Process and Thread ID**: **`bpf_get_current_pid_tgid()`** retrieves the process ID and thread group ID of the current process.
    - **Timestamp**: **`bpf_ktime_get_ns()`** gets the current time in nanoseconds.
    - **Socket Family**: Retrieves the socket family (type of network protocol, e.g., IPv4, IPv6) from the socket structure.
    - **User ID**: **`bpf_get_current_uid_gid()`** fetches the user and group ID of the current process.
    - **Port and IP Address**: Extracts the port number and IP address from the **`sockaddr_in`** structure.
    - **Process Name**: **`bpf_get_current_comm()`** gets the name of the current process.
    
    ### **Submit the Event**
    
    ```c
    events.perf_submit(ctx, &netevent, sizeof(netevent));
    ```
    
    - **Perf Event Submission**: Uses the BPF helper function **`perf_submit()`** to send the **`netevent`** data structure to user space via a perf event. This allows the user space program monitoring the eBPF map to receive and process this data.
    
    In short the code checks whether the address is IPv4 or not. If it’s IPv4 it populates the relevant fields and passes it to the perf buffer to be later used by the userspace code.
    

 **`bpf_sock["events"]`** accesses a BPF table named **`events`** defined in the **`ebpfshield.c`** file.

**`.open_perf_buffer(process_netevent)`**: This operates on a table as defined in BPF as BPF_PERF_OUTPUT(), and associates the callback Python function `**callback**` to be called when data is available in the perf ring buffer. This is part of the recommended mechanism for transferring per-event data from kernel to user space.

### ebpf_monitor

```python
elif args.feature == "ebpf_monitor":
    #delete me
    #b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
    bpf_kprobe = BPF(text=C_BPF_KPROBE)
    bpf_kprobe.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
    bpf_kprobe.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
    #delete me

    bpf_sock = BPF(text=BPF_SOCK_TEXT)

    function_dns_matching = bpf_sock.load_func("dns_matching", BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(function_dns_matching, "")

    print('The program is running. Press Ctrl-C to abort.')

    bpf_sock["dns_events"].open_perf_buffer(print_dns)
```

When we pass the `ebpf_monitor` with `--feature` flag the above code snippet executes.

First we create a BPF object with the code snippet defined as `C_BPF_KPROBE`. Then we attach the kernel functions tcp_sendmsg and udp_sendmsg with [`trace_tcp_sendmsg`](https://www.notion.so/eBPFShield-3af611b3a4424845bf919e3ed52f9efd?pvs=21) and `[trace_udp_sendmsg](https://www.notion.so/eBPFShield-3af611b3a4424845bf919e3ed52f9efd?pvs=21)` respectively.

```python
    bpf_kprobe = BPF(text=C_BPF_KPROBE)
    bpf_kprobe.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
    bpf_kprobe.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
```

The following code snippet does some similar processing, it takes `BPF_SOCK_TEXT` as the eBPF code to create the BPF object.

```python
    bpf_sock = BPF(text=BPF_SOCK_TEXT)

    function_dns_matching = bpf_sock.load_func("dns_matching", BPF.SOCKET_FILTER)
    BPF.attach_raw_socket(function_dns_matching, "")

    print('The program is running. Press Ctrl-C to abort.')

    bpf_sock["dns_events"].open_perf_buffer(print_dns)
```

Finally infinity loop is used to continuously read from the perf buffer.

```python
while 1:
    try:
        bpf_sock.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
```
