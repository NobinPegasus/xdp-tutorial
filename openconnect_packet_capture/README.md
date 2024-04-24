### Commands to deploy the code:

```bash
git clone https://github.com/inspektors-io/xdp-tutorial.git
git checkout -b nobin origin/nobin
git pull origin nobin
./remove-filter-and-qdisc.sh
./build-and-run.sh
```

Change the INTERFACE=tun0 to the interface name we want our code to attach. Replace all tun0 with that interface name.
Inside main.go `const INTERFACE = "tun0"` change it accordingly.

### PoC(Proof of Concept):

Here I used curl command to visit https://nobinpegasus.github.io

It’s IP is 185.199.111.153

When we attach our tc/eBPF code to the tunnel interface we are able to observe this destination ip.

![Screenshot from 2024-04-21 10-50-37](https://github.com/inspektors-io/xdp-tutorial/assets/158417040/451652da-13c9-4e39-acfd-4c55670b1898)


![Screenshot from 2024-04-21 10-50-18](https://github.com/inspektors-io/xdp-tutorial/assets/158417040/51198ef0-3ca0-4767-9a78-413c4e38282a)


### Workflow Diagram:

![workflow2 drawio](https://github.com/inspektors-io/xdp-tutorial/assets/158417040/aca90ec6-d262-4351-8cdb-f1e9376923ba)

### **Kernel Space eBPF Code:**

![openconnect drawio](https://github.com/inspektors-io/xdp-tutorial/assets/158417040/ada3b4b6-6260-4d42-975e-151138456857)


The XDP is unable to capture packets from virtual interface. Here which is a tunneling interface. But since tc comes later in the stack it can very well be attached to tunnel interfaces (vpnX, tunX).
Since the OpenConnect does end to end encryption, capturing the inner Destination packet is pretty complicated from the physical interfaces point of view. But attaching tc/eBPF code to the virtual adapter we can monitor the actual traffic (real destination address of the user).

The bpf.c code:

```
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include "include/ip.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include "include/helpers.h"

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

    // if (skb->protocol != bpf_htons(ETH_P_IP))
    //     return TC_ACT_OK;

    eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    ip = data + 0;
    // ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    __u32 source = bpf_ntohl(ip->addrs.saddr);
    __u32 dest = bpf_ntohl(ip->addrs.daddr);

    //extract the port from tcp or ip headers
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

```

First, we import the necessary headers. And define the protocol representations.

```jsx
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include "include/ip.h"
#include <linux/tcp.h>
#include <linux/udp.h>
#include "include/helpers.h"

#define ETH_P_IP 0x0800 /* Internet Protocol Packet */
#define PROTO_TCP 6
#define PROTO_UDP 17
```

We then define a struct that we will use to populate the eBPF map.

```jsx
struct packetdets {
    __u32 source;
    __u16 source_port;
    __u32 dest;
    __u16 dest_port;
    __u8 ip_protocol;
};
```

Then we define the eBPF map.

```jsx
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct packetdets);
    __type(value, __u64);
    __uint(max_entries, 1000);
} pkt_count SEC(".maps");
```

`BPF_MAP_TYPE_HASH` and `BPF_MAP_TYPE_PERCPU_HASH` provide general purpose hash map storage. Both the key and the value can be structs, allowing for composite keys and values.

The kernel is responsible for allocating and freeing key/value pairs, up to the max_entries limit that you specify. 
Here we are creating the eBPF map and putting it inside .maps section. We then define the main bpf function and put it inside a memory section named tc_prog. 

```jsx
int tc_main(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    // if (skb->protocol != bpf_htons(ETH_P_IP))
    //     return TC_ACT_OK;

    eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    ip = data + 0;
    // ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    __u32 source = bpf_ntohl(ip->addrs.saddr);
    __u32 dest = bpf_ntohl(ip->addrs.daddr);

    //extract the port from tcp or ip headers
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
```

A normal packet structure is eth→ip→tcp/udp. Packet structures can be monitored using wireshark or tshark which is a cli version of wireshark.

![Screenshot from 2024-04-18 10-48-40](https://github.com/inspektors-io/xdp-tutorial/assets/158417040/a4958ebf-52fb-401b-949c-bc94c3d853bd)


The openconnect packet is a bit different monitored from tunnel interface.

![Screenshot from 2024-04-18 10-54-39](https://github.com/inspektors-io/xdp-tutorial/assets/158417040/07d822ea-8096-4f9c-a8e2-72e035dcf3cf)


First we take the pointer of the starting of the data. sk_buff is the **main networking structure representing a packet**.

Since in openconnect packet we see it’s directly raw:ip:udp.
We can safely skip the ethernet part.  So we add 0 bits to data. 

`TC_ACT_OK (0)`: Terminate the packet processing pipeline and allows the
packet to proceed. If the data is corrupted (void *)ip + sizeof(struct iphdr) exceeds the data_end so we don’t process it.

```jsx
int tc_main(struct __sk_buff *skb)
{
    void *data_end = (void *)(__u64)skb->data_end;
    void *data = (void *)(__u64)skb->data;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;

    // if (skb->protocol != bpf_htons(ETH_P_IP))
    //     return TC_ACT_OK;

    eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    ip = data + 0;
    // ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;
```

We then start parsing the IP part. Since network bit order and host bit order is different we typecast the big endian to little endian with bpf_ntohl function.

```jsx
    __u32 source = bpf_ntohl(ip->addrs.saddr);
    __u32 dest = bpf_ntohl(ip->addrs.daddr);
```

We then start processing the tcp/udp packets of layer 4. It checks whether the packet is udp or tcp. If it’s udp it copies the tcp→source to source_port and tcp->dest to  dest_port. For udp it uses udp→source and udp→dest. We also check if the packets are corrupted and not at each stage and if they are corrupted we terminate processing.

```jsx
//extract the port from tcp or ip headers
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
```

We then populate the struct fields with respective valid data.

```jsx
    struct packetdets key = {
        .source = source,
        .source_port = source_port,
        .dest = dest,
        .dest_port = dest_port,
        .ip_protocol = ip_proto,
    };
```

Finally we use bpf_map_lookup_elem to check if the the respected entry is present on pkt_count bpf map or not using key. If the entry is present it returns it’s value and then increases the value to keep counting.

Otherwise if the entry isn’t found inside the map, it initializes the value with 1 and respective key as the key. 

```jsx
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 value = 1;
        bpf_map_update_elem(&pkt_count, &key, &value, BPF_ANY);
    }
```

Finally we print the bpf_trace log to print remote_ip4. It’s used for debugging. Then we terminate the processing.

```jsx
   char hello_str[] = "hello pkt ipv4: %u";
    bpf_trace_printk(hello_str, sizeof(hello_str), &skb->remote_ip4);
    return TC_ACT_OK;
}
```

This is the mandatory licensing part. Only compatible libraries can be used with them e.g. A library with non GPL can’t be used inside GPL eBPF code.

```jsx
char __license[] SEC("license") = "Dual MIT/GPL";
```

### PoC:

### UserSpace Code:

```bash
package main

// from https://d0u9.io/use-cilium-ebpf-to-compile-and-load-tc-bpf-code/

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tc bpf/bpf.c -- -I./bpf

func InttoIP4(ipInt uint32) string {
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

const INTERFACE = "tun0"

func main() {
	var err error

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
		// Parent:    netlink.HANDLE_MIN_INGRESS, //direction
		Parent:   netlink.HANDLE_MIN_EGRESS,
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
	for {
		select {
		case <-tick:
			log.Printf("==========")
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
				}
			}
			log.Printf("")
		case <-stop:
			log.Printf("Received signal stopping.")
			return
		}
	}
}

```

First we declare main.go is part of the package main. Then we import the required packages.

```bash
package main

// from https://d0u9.io/use-cilium-ebpf-to-compile-and-load-tc-bpf-code/

import (
	"log"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)
```

Then we define the go:generate. Here we run the bpf2go tool with `go run github.com/cilium/ebpf/cmd/bpf2go`, we declare that it’s a `tc`(traffic control) type of code, it uses file `bpf.c` as input, `--` denotes that command should be seperated from the arguements,  `-I./bpf` means we are using the headers from `./bpf` directory.

```bash
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go tc bpf/bpf.c -- -I./bpf
```

Then we define InttoIP4 to represent integer as ipv4 format. We also define ntohs to convert network byte order(big-endian) into host byte order(little-endian).  

```bash
func InttoIP4(ipInt uint32) string {
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
```

We then define the interface that we going to attach the eBPF code.

`const INTERFACE = "tun0"`

Then we define the main function. Inside main we define a tcObjects structure.

```bash
func main() {
	var err error

	// Load bpf programs and maps into the kernel
	objs := tcObjects{}
	if err := loadTcObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()
```

- tcObjects struct
    
    ```bash
    // tcObjects contains all objects after they have been loaded into the kernel.
    //
    // It can be passed to loadTcObjects or ebpf.CollectionSpec.LoadAndAssign.
    type tcObjects struct {
    	tcPrograms
    	tcMaps
    }
    ```
    
- loadTcObjects()
    
    ```bash
    // loadTcObjects loads tc and converts it into a struct.
    //
    // The following types are suitable as obj argument:
    //
    //	*tcObjects
    //	*tcPrograms
    //	*tcMaps
    //
    // See ebpf.CollectionSpec.LoadAndAssign documentation for details.
    func loadTcObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
    	spec, err := loadTc()
    	if err != nil {
    		return err
    	}
    
    	return spec.LoadAndAssign(obj, opts)
    }
    ```
    
    `LoadAndAssign()` loads Maps and Programs into the kernel and assigns them to a struct.
    
    `loadTc()`  returns the embedded CollectionSpec for tc.
    
    The details of CollectionSpec and LoadAndAssign is defined here: [https://www.notion.so/packet_counter-f40b3c8aa6c54f1593b41d77ff8783be?pvs=4#2f3e8579adac4c6491fb01fd6b18f552](https://www.notion.so/packet_counter-f40b3c8aa6c54f1593b41d77ff8783be?pvs=21)
    

`defer` state allows a function to postpone the execution of a statement until the surrounding function has completed. The objs.close() is called after all the processing is done.

`progFd := objs.TcMain.FD()` 
is used to get the file descriptor of the main tc function.

```bash
// tcPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadTcObjects or ebpf.CollectionSpec.LoadAndAssign.
type tcPrograms struct {
	TcMain *ebpf.Program `ebpf:"tc_main"`
}
```

Then we get the interface. `LinkByName` finds a link by name and returns a pointer to the object.

```bash
	intf, err := netlink.LinkByName(INTERFACE)
	if err != nil {
		log.Fatalf("cannot find %s: %v", INTERFACE, err)
	}
```

![Screenshot from 2024-04-20 17-30-38](https://github.com/inspektors-io/xdp-tutorial/assets/158417040/cc9dd227-fa36-4af1-8303-1f2a78800835)

```bash
	attrs := netlink.QdiscAttrs{
		LinkIndex: intf.Attrs().Index, //Interface index
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
```

- QdiscAttrs
    
    ```bash
    type QdiscAttrs struct {
    	LinkIndex int
    	Handle    uint32
    	Parent    uint32
    	Refcnt    uint32 // read only
    }
    ```
    
    QdiscAttrs represents a netlink qdisc. A qdisc is associated with a link, has a handle, a parent and a refcnt. 
    
    - **LinkIndex**: This is the index of the network interface that the queuing discipline (qdisc) is being applied to. Each network interface on a Linux system has a unique index to identify it. In this code, **`intf.Attrs().Index`** is used to get the index of the network interface **`intf`**.
    - **Handle**: A handle is a unique identifier for a qdisc or class within the Linux Traffic Control subsystem. It’s represented as a 16-bit hexadecimal number and is used to reference a specific qdisc or class in traffic control commands. In this code, **`netlink.MakeHandle(0xffff, 0)`** is used to create a handle with a major number of **`0xffff`** and a minor number of **`0`**. The major number is used to identify the qdisc, and the minor number is used to identify individual classes within a classful qdisc. Since **`clsact`** is a classless qdisc, it doesn’t have any classes, so the minor number is **`0`**.
    - **Parent**: The parent field is used to specify the parent qdisc of a qdisc. The root qdisc of a network interface has a special parent handle, **`netlink.HANDLE_ROOT`**. If a qdisc is a direct child of the root qdisc, its parent field would be set to **`netlink.HANDLE_ROOT`**. In this code, **`Parent: netlink.HANDLE_CLSACT,`** is setting the parent of the qdisc to **`netlink.HANDLE_CLSACT`**. The **`clsact`** qdisc is a special, classless qdisc that is typically used as the root qdisc for traffic classification and action.

Queuing disciplines (`qdiscs`) help with queuing up and, later, scheduling of traffic transmission by a network interface. A `qdisc` has two operations;

- enqueue requests so that a packet can be queued up for later transmission and
- dequeue requests so that one of the queued-up packets can be chosen for immediate transmission.

clsact is a special kind of qdisc that can handle egress and ingress data. The *handle* is the magic userspace way of naming a particular qdisc,

**Declaring qdisc**

```bash
	// declare the qdisc
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
```

We use eBPF to implement a complicated qdisc.

- Applications of Qdisc
    
    TC is a powerful, yet complex framework (and it is [somewhat documented](https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/#about-tc)). It relies on
    the notions of “queueing disciplines” (*qdiscs*), “classes”, “classifiers”
    (*filters*) and actions. A very simplified description might be the following:
    
    1. The user defines a *qdisc*, a shaper that applies a specific policy to
    different *classes* of traffic. The *qdisc* is attached to a network
    interface (ingress or egress).
    2. The user defines *classes* of traffic, and attach them to the *qdisc*.
    3. *Filters* are attached to the *qdisc*. They are used to classify the traffic
    intercepted on this interface, and to dispatch the packets into the
    different *classes*. A *filter* is run on every packet, and it can return
    one of the following values:
        - 0, which denotes a mismatch (for the default *class* configured for this
        *filter*). Next *filters*, if any, are run on the packet.
        - 1, which denotes the default classid configured for this *filter*,
        - any other value will be considered as the *class* identifier refering to
        the *class* where the packet should be sent, thus allowing for
        non-linear classification.
    4. Additionally, an *action* to be applied to all matching packets can be added
    to a filter. For example, selected packets could be dropped, or mirrored on
    another network interface, etc.
    5. New nested *qdiscs* can be attached to the *classes*, and receive *classes*
    in their turn. The complete policy diagram is in fact a tree spanning under
    the root *qdisc*. But we do not need this information for the rest of the
    article.

**Adding the qdisc to the system**

```go
	// add the qdisc
	if err := netlink.QdiscAdd(qdisc); err != nil {
		log.Fatalf("cannot add clsact qdisc: %v", err)
	}
```

- QdiscAdd function
    
    ```bash
    // QdiscAdd will add a qdisc to the system.
    // Equivalent to: `tc qdisc add $qdisc`
    func QdiscAdd(qdisc Qdisc) error {
    	return pkgHandle.QdiscAdd(qdisc)
    }
    ```
    

Now we have defined and attached the qdisc. It’s time for us to also define the filter that will be applied to this qdisc. The filter attributes are given below:

```go
	//filter attributes
	filterAttrs := netlink.FilterAttrs{
		LinkIndex: intf.Attrs().Index,
		// Parent:    netlink.HANDLE_MIN_INGRESS, //direction
		Parent:   netlink.HANDLE_MIN_EGRESS,
		Handle:   netlink.MakeHandle(0, 1),
		Protocol: unix.ETH_P_ALL,
		Priority: 1,
	}
```

- Explanation of filterAttrs
    - **`LinkIndex int`**: This is the index of the network link (like an Ethernet or Wi-Fi interface) that this filter is associated with. Each network interface on a system is assigned a unique index.
    - **`Handle uint32`**: This is a unique identifier for this filter. It’s used to reference this specific filter when performing operations like updating or deleting it.
    - **`Parent uint32`**: This is the handle of the parent filter of this filter. Filters can be arranged in a hierarchy, and this field specifies the parent in that hierarchy. The root filter of a device should have a parent equal to **`HANDLE_ROOT`**.
    - **`Priority uint16`**: This is the priority of the filter. Lower values indicate higher priority. When multiple filters could match a packet, the one with the highest priority (i.e., the lowest numerical value) is used.
    - **`Protocol uint16`**: This specifies the protocol that this filter applies to, using constants from the **`unix`** package. For example, **`unix.ETH_P_*`** constants can be used to specify various Ethernet protocols.
    
    Then we declare the BpfFilter:
    
    ```go
    	//declare the BPF filter
    	filter := &netlink.BpfFilter{
    		FilterAttrs:  filterAttrs,
    		Fd:           progFd,
    		Name:         "hi-tc",
    		DirectAction: true,
    	}
    ```
    
    It uses the previously declared attributes and uses the eBPF program passed as file descriptor. DirectAction means the return value of the eBPF code can be directly used to take action on the packet without adding any additional tc action object.
    
    - Detailed explanation of Direct Action:
        
        For a number of use cases, eBPF classifiers alone are enough to filter and process the packets, and do not need additional *qdiscs* or *classes* to be attached to them. This is particularly true when packets should be filtered (passed, or dropped) at the TC interface level. Classifiers do need, however, an additional action to actually drop the packets: the value returned by a classifier cannot be used to tell the system to drop a packet.
        
        To avoid to add such simple TC actions and to simplify those use cases where
        the classifier does all the work, a new flag was added to TC for eBPF
        classifiers: `direct-action`, also available as `da` for short. This flag, used
        at *filter* attach time, tells the system that the return value from the
        ***filter*** should be considered as the one of an ***action*** instead. This
        means that an eBPF program attached as a TC classifier can now return
        `TC_ACT_SHOT`, `TC_ACT_OK`, or another one of the reserved values. And it is
        interpreted as such: no need to add another TC *action* object to drop or
        mirror the packet. In terms of performance, this is also more efficient,
        because the TC subsystem no longer needs to call into an additional action
        module external to the kernel.
        
    
    Then we add the filter to the system.
    
    ```go
    	//add the filter
    	if err := netlink.FilterAdd(filter); err != nil {
    		log.Fatalf("cannot attach bpf object to filter: %v", err)
    	}
    ```
    
    - FilterAdd function
        
        ```bash
        // FilterAdd will add a filter to the system.
        // Equivalent to: `tc filter add $filter`
        func FilterAdd(filter Filter) error {
        	return pkgHandle.FilterAdd(filter)
        }
        ```
        

Then we just print a log message:
`log.Printf("Counting packets on %s...", INTERFACE)`

The following code sends a signal after every one second. It can store 5 unread signals.Then ctrl+c is used to stop this ticking.

```go
	//repeatedly output the map contents
	tick := time.Tick(time.Second)
	stop := make(chan os.Signal, 5)
	signal.Notify(stop, os.Interrupt)
```

- **`tick := time.Tick(time.Second)`**: This line creates a new ticker that ticks every second. A tick is a signal sent after a specified duration.
- **`stop := make(chan os.Signal, 5)`**: This line creates a new channel that can receive **`os.Signal`** values. The channel has a buffer size of 5, meaning it can hold up to 5 unread signals.
- **`signal.Notify(stop, os.Interrupt)`**: This line sets up **`stop`** to receive interrupt signals. When an interrupt signal is received (like when you press **`Ctrl+C`**), it will be sent to the **`stop`** channel.

The PktCount struct defined previously to store the eBPF map contents are retrived using objs.PktCount here.

```bash
	pktCount := objs.PktCount
```

It then uses an infinite loop and waits until of the select case that is either a tick or a stop signal.

If case is tick which ticks in every one second. It creates a struct variable. Inside the struct the eBPF map is iterated and the map keys are extracted. The `[entries.Next](http://entries.Next)` decodes the next key and value. It uses the key to fetch the entry and keeps the count. It then fetches the source Ip, source port, destination Ip and ports. and prints those. Finally when the stop signal (ctrl+c is pressed) is received it returns and the infinity loop is exited.

```bash
	for {
		select {
		case <-tick:
			log.Printf("==========")
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
				}
			}
			log.Printf("")
		case <-stop:
			log.Printf("Received signal stopping.")
			return
		}
	}
```
