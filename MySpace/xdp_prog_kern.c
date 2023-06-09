/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

/* Defines xdp_stats_map */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

static __always_inline void update_iph_checksum(struct iphdr *iph) 
{
    __u16 *next_iph_u16 = (__u16 *)iph;
    __u32 csum = 0;
    iph->check = 0;
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < sizeof(*iph) >> 1; i++) {
        csum += *next_iph_u16++;
    }   
 
    int i = 0;
    while (csum >> 16 && i < 4)
    {
        csum = (csum & 0xffff) + (csum >> 16);
        i++;
    }
    iph->check = (__u16) ~csum;
}

SEC("xdp_TTL_rewrite")
int xdp_TTL_rewrite_func(struct xdp_md *ctx)
{
    bpf_printk("BPF triggered from PID\n");
    int action              = XDP_PASS;
    int eth_type, ip_type   = 0;
    struct ethhdr *eth      = NULL;
    struct iphdr *iphdp     = NULL;
    __u8	TTL_N           = 0;

    void *data_end          = (void *)(long)ctx->data_end;
    void *data              = (void *)(long)ctx->data;
    struct hdr_cursor nh    = { .pos = data };

    // __u32 saddr;
    // __u32 csum = 0;

    eth_type = parse_ethhdr(&nh, data_end, &eth);

    bpf_printk("eth_type %d.\n", eth_type);
    if (eth_type < 0){
        action = XDP_ABORTED;
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdp);
        bpf_printk("ip_type %d.\n", ip_type);
        if (iphdp) {
            // saddr = iphdp->saddr;
            TTL_N = iphdp->ttl;
            bpf_printk("TTL_N %d.\n", TTL_N);
            action = XDP_PASS;
            goto out;
        }
    } else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        action = XDP_PASS;
        goto out;
    } else {
        action = XDP_ABORTED;
        goto out;
    }
    
out:
    return xdp_stats_record_action(ctx, action);
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";