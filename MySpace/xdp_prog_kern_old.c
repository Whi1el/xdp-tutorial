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

static __always_inline int Confusion_TTL(struct iphdr* iphdp)
{
    if (iphdp->ttl == 64 || iphdp->ttl == 128 || iphdp->ttl == 256)
    {
        __u32 random_num = bpf_get_prandom_u32();
        iphdp->ttl = 64 - (random_num & 0x3);
        return 1;
    }
    return 0;
}


static __always_inline void update_iph_checksum(struct iphdr *iph) 
{
    __u16 *next_iph_u16 = (__u16 *)iph;
    __u32 csum = 0;
    iph->check = 0;
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < sizeof(*iph) >> 1; i++) 
    {
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

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
        {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    return ~csum;
}

static __always_inline void ipv4_l4_csum(void* data_start, __u32 data_size, __u64* csum, struct iphdr* iph)
{
    struct tcphdr* tcph = data_start;
    __u16 tcpdata_len = bpf_htons(iph->tot_len) - (tcph->doff * 4) - (iph->ihl * 4);
    *csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
    *csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
    *csum += __builtin_bswap32((__u32)(iph->protocol));                                   // 尝试能不能改成 BPF 的格式？为什么这么写？
    *csum += __builtin_bswap32((__u32)(data_size));
    
    /*计算末尾不足4字节的字节数目，n为需要填充的字节数目*/
    int n = 0;
    while(((data_size-n)%3) != 0)
    {
        n++;
    }

    if (tcpdata_len > 0 && n > 0)
    {
        *csum  += __builtin_bswap32((__u32)(256));
    }

    if (data_size > 0)
    {
        bpf_csum_diff(0, 0, data_start, data_size-n, *csum);
    }

    __u16* restdata = (__u16*)((unsigned char*)data_start + (data_size - n));
    while (n > 1)
    {
        *csum += *restdata++;
        n -= 2;
    }

    if (n == 1)
    {
        __u16 answer;
        answer = (*(unsigned char*)restdata);
        *csum += answer;
    }

    *csum = csum_fold_helper(*csum);
}


SEC("xdp_TTL_rewrite")
int xdp_TTL_rewrite_func(struct xdp_md *ctx)
{
    bpf_printk("Start\n");
    int action              = XDP_PASS;
    int eth_type, ip_type   = 0;
    struct ethhdr *eth      = NULL;
    struct iphdr *iphdp     = NULL;

    void *data_end          = (void *)(long)ctx->data_end;
    void *data              = (void *)(long)ctx->data;
    struct hdr_cursor nh    = { .pos = data };

    



    /*解析 ETH 包头*/
    eth_type = parse_ethhdr(&nh, data_end, &eth);
    
    /*判断是否能够解析成功*/
    if (eth_type < 0){
        action = XDP_ABORTED;
        goto out;
    }

    if (eth_type == bpf_htons(ETH_P_IP)) {
        /*判断 ETH 类型是否是 IPv4*/
        ip_type = parse_iphdr(&nh, data_end, &iphdp);
        bpf_printk("ip_type %d.\n", ip_type);

        if (iphdp) {
            if (!Confusion_TTL(iphdp)){
                action = XDP_PASS;
                goto out;
            }
        }

            update_iph_checksum(iphdp);
            action = XDP_PASS;
            goto out;
    } 
    else if (eth_type == bpf_htons(ETH_P_IPV6)) {
        /*判断 ETH 类型是否是 IPv6*/
        action = XDP_PASS;
        goto out;
    } 
    else {
        /*既不是IPv4也不是IPv6*/
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