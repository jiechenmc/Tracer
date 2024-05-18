// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <asm-generic/types.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 100);
} pkt_count SEC(".maps");

static __always_inline int parse_ip_src_addr(struct xdp_md *ctx, __u32 *ip_src_addr)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // First, parse the ethernet header.
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return 0;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        // The protocol is not IPv4, so we can't parse an IPv4 source address.
        return 0;
    }

    // Then parse the IP header.
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
    {
        return 0;
    }

    // Return the source IP address in network byte order.
    *ip_src_addr = (__u32)(ip->saddr);
    return 1;
}

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{

    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);

    if (count)
    {
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct ethhdr *eth = data;
        *count = data_end - data;

        bpf_printk("packet size is %d", eth->h_dest);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";