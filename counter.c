// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <asm-generic/types.h>
#include <linux/dns_resolver.h>

// Define htons function for byte order conversion, specific to BPF's environment
#define bpf_htons(x) ((__be16)___constant_swab16((x)))

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 100);
} pkt_count SEC(".maps");

SEC("xdp")

int xdp_pass(struct xdp_md *ctx)
{

    void *data_end = (void *)(long)ctx->data_end; // end of data from context
    void *data = (void *)(long)ctx->data;         // start of data from context

    // Point to the start of the ethernet header within the data
    struct ethhdr *eth = data;

    // Verify that the ethernet header is within the bounds of the data
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return XDP_PASS;
    }

    // Check if the ethernet frame contains an IP packet (ETH_P_IP is the IPv4 EtherType) converts host to network bytes order
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(*eth); // Point to the IP header after the ethernet header
    // Verify that the IP header is within the bounds of the data
    if ((void *)iph + sizeof(*iph) > data_end)
    {
        bpf_printk("XDP: IP header validation failed\n");
        return XDP_PASS;
    }

    // ALLOW ALL NON TCP PACKETS THROUGH
    if (iph->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    bpf_printk("IP address is %pI4\n | %u", &iph->saddr, iph->saddr);

    //
    struct tcphdr *tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);

    if ((void *)(tcph + 1) > data_end)
    {
        return XDP_PASS;
    }

    bpf_printk("PACKET DEST PORT %u\n", bpf_htons(tcph->dest));

    __u32 key = iph->saddr;

    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);

    if (count)
    {
        __sync_fetch_and_add(count, 1);
    }
    else
    {
        __u64 value = 1;
        bpf_map_update_elem(&pkt_count, &key, &value, BPF_ANY);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";