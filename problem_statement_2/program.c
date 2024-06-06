#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h> 
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") process_map = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(char[16]),   // Size of the process name
    .value_size = sizeof(__u16),     // Size of the allowed port
    .max_entries = 1,
};

SEC("xdp")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    char process_name[16] = "myprocess";
    __u16 *allowed_port;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcph = (struct tcphdr *)(iph + 1);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Look up the allowed port for the specified process
    allowed_port = bpf_map_lookup_elem(&process_map, &process_name);
    if (!allowed_port)
        return XDP_PASS;

    // Check if the packet is from the specified process and not destined for the allowed port
    if (bpf_get_current_comm(process_name, sizeof(process_name)) == 0 &&
        __constant_htons(tcph->dest) != *allowed_port) {
        // Drop the packet
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
