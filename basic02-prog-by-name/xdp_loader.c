/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Specify BPF-object --filename to load \n"
	" - and select BPF section --progsec name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"

static const char *default_filename = "xdp_prog_kern.o";
static const char *default_progsec = "xdp_pass";

static const struct option_wrapper long_options[] = {										// 该数据结构用于解析命令行参数
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"offload-mode",no_argument,		NULL, 3 },
	 "Hardware offload XDP program to NIC"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

/* Lesson#1: More advanced load_bpf_object_file and bpf_object */
struct bpf_object *__load_bpf_object_file(const char *filename, int ifindex)				// *filename 文件指针 ifindex 网络接口索引，加载BPF目标文件
{																							// 接收文件名和网络接口索引，从BPF-ELF对象文件中提取BPF字节码，
	/* In next assignment this will be moved into ../common/ */								// 并通过bpf系统调用将其加载到内核中
	int first_prog_fd = -1;																	// 用于在后续的长须中获取BPF程序的文件描述符
	struct bpf_object *obj;																	// 指向bpf_object类型的指针
	int err;

	/* Lesson#3: This struct allow us to set ifindex, this features is used
	 * for hardware offloading XDP programs.
	 */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,													// 声明文件类型
		.ifindex	= ifindex,																// 接口索引
	};
	prog_load_attr.file = filename;															// filename 是一个指向字符数组的指针

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);						// & 操作符用于获取变量的内存地址，因为函数的原型需要接收指针作为参数
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return NULL;
	}

	/* Notice how a pointer to a libbpf bpf_object is returned */
	return obj;
}

/* Lesson#2: This is a central piece of this lesson:
 * - Notice how BPF-ELF obj can have several programs
 * - Find by sec name via: bpf_object__find_program_by_title()
 */
struct bpf_object *__load_bpf_and_xdp_attach(struct config *cfg)							// 函数接受一个指向config结构的指针作为参数，加载BPF和XDP属性
{																							// 加载BPF-ELF对象文件，
	/* In next assignment this will be moved into ../common/ */								// 并将其中一个BPF程序附加到XDP（Express Data Path）网络设备的链接层挂钩。
	struct bpf_program *bpf_prog;															// 
	struct bpf_object *bpf_obj;																// 
	int offload_ifindex = 0;																// 用于存储在哪个网络接口执行硬件卸载
	int prog_fd = -1;
	int err;

	/* If flags indicate hardware offload, supply ifindex */
	if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)													// 检查配置结构中的标志位，XDP_FLAGS_HW_MODE是否被设置，也就是说硬件卸载模式是否启用
		offload_ifindex = cfg->ifindex;														// 程序将在硬件卸载模式下运行

	/* Load the BPF-ELF object file and get back libbpf bpf_object */
	bpf_obj = __load_bpf_object_file(cfg->filename, offload_ifindex);						// 若offload_ifindex==0，则XDP程序将在主机的CPU上运行，即在用户空间加载BPF-ELF对象文件
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", cfg->filename);
		exit(EXIT_FAIL_BPF);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	/* Find a matching BPF prog section name */
	bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);					// 通过该代码我们可以在BPF对象中选择一个特定的BPF程序来执行，返回指向该程序节的bpf_program结构体指针
	if (!bpf_prog) {
		fprintf(stderr, "ERR: finding progsec: %s\n", cfg->progsec);
		exit(EXIT_FAIL_BPF);
	}

	prog_fd = bpf_program__fd(bpf_prog);													// 获取BPF程序对应的文件描述符
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(EXIT_FAIL_BPF);
	}

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
	err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);							// 使用了xdp_link_attach函数来将BPF程序附加到指定的网络接口的XDP hook上
	if (err)
		exit(err);

	return bpf_obj;																			
	/* 返回BPF对象结构体指针的主要原因是在程序的其他部分可能需要访问BPF程序对象的属性
	 * 和方法，例如BPF程序的映射表、调试信息等。
	*/ 
}

static void list_avail_progs(struct bpf_object *obj)
{
	struct bpf_program *pos;

	printf("BPF object (%s) listing avail --progsec names\n",
	       bpf_object__name(obj));

	bpf_object__for_each_program(pos, obj) {
		if (bpf_program__is_xdp(pos))
			printf(" %s\n", bpf_program__title(pos, false));
	}
}

int main(int argc, char **argv)
{
	struct bpf_object *bpf_obj;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,						// XDP_FLAGS_UPDATE_IF_NOEXIST:若不存在XDP程序，则更新XDP挂钩
		.ifindex   = -1,																	// XDP_FLAGS_DRV_MODE:以驱动模式加载XDP程序
		.do_unload = false,																	// ifindex表示网络接口尚未设置，do_unload表示默认情况下目标不是卸载程序
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));							// 拷贝默认的文件名
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));							// 拷贝默认的段名
	/* Cmdline options can change these */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);							// 参数数量、字符指针数组、定义了支持的长选项、结构体示例指针、文档信息

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);

	bpf_obj = __load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;

	if (verbose)
		list_avail_progs(bpf_obj);

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}
	/* Other BPF section programs will get freed on exit */
	return EXIT_OK;
}
