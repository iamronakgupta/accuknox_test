#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>  // Ensure to include this for __u32 definition

#define bpf_printk(fmt, ...) \
    ({ \
        char ____fmt[] = fmt; \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__); \
    })

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);  // Use __u32 instead of u32
    __type(value, __u32);  // Use __u32 instead of u32
} drop_port SEC(".maps");

SEC("xdp/tcp_drop")
int drop_tcp_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    __u32 key = 0;
    __u32 *port;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    port = bpf_map_lookup_elem(&drop_port, &key);
    if (port && tcph->dest == __constant_htons(*port)) {
        bpf_printk("Dropping TCP packet on port %d\n", *port);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
