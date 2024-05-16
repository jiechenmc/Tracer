// +build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
} pkt_count SEC(".maps");

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

        bpf_printk("packet size is %d", *count);
    }

    return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";