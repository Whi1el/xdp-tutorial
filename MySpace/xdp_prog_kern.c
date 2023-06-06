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


static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

static __always_inline void ipv4_csum(void *data_start, int data_size,
				      __u32 *csum)
{
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
    bpf_printk("csum_in %d.\n", *csum);
	*csum = csum_fold_helper(*csum);
    bpf_printk("csum_in2 %d.\n", *csum);
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

    __u32 saddr;
    __u32 csum = 0;

    /*解析以太网包头*/
    eth_type = parse_ethhdr(&nh, data_end, &eth);

    bpf_printk("eth_type %d.\n", eth_type);
    if (eth_type < 0){
        action = XDP_ABORTED;
        goto out;
    }

    // 重构注释的代码
    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdp);
        bpf_printk("iphdr %d.\n", ip_type);
        /*获取源地址*/
        if (iphdp) {
            saddr = iphdp->saddr;
            bpf_printk("saddr %d.\n", saddr);
            bpf_printk("htons_saddr %d.\n", bpf_htonl(saddr));
            TTL_N = iphdp->ttl;
            bpf_printk("TTL_N %d.\n", TTL_N);
            iphdp->ttl = 63;
            bpf_printk("TTL_N %d.\n", iphdp->ttl);

            bpf_printk("iphdp->check %d.\n", iphdp->check);

            ipv4_csum(iphdp, sizeof(struct iphdr), &csum);
            bpf_printk("csum3 %d.\n", csum);
            iphdp->check = csum;
            
            bpf_trace_printk("iphdp->check %d.\n", iphdp->check);
            // iphdp->ttl = 64;
            bpf_printk("TTL_N %d.\n", iphdp->ttl);

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