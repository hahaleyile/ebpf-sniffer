#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "xdppass.h"

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 4096); // Set the ring buffer size to 16MB
} ringBuffer SEC(".maps");

SEC("xdp")
int xdp_pass(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    unsigned long len = data_end - data;

    // bpf_printk("Data: %llu",data);

    // Reserve space in the ring buffer for the packet_info structure
    struct packet_info *pkt_info = bpf_ringbuf_reserve(&ringBuffer, sizeof(struct packet_info), 0);
    if (!pkt_info)
    {
        return XDP_PASS;
    }

    // bpf_printk("before read: %llu",pkt_info->data);

    // Fill the packet_info structure with metadata and packet data
    pkt_info->timestamp = bpf_ktime_get_ns();
    pkt_info->len = len;
    bpf_probe_read_kernel(pkt_info->data, 1500, data);

    // bpf_printk("After read kernel: %llu",pkt_info->data);

    // Submit the packet_info structure to the ring buffer
    bpf_ringbuf_submit(pkt_info, 0);

    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
