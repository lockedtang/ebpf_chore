// #include <linux/bpf.h>
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
// #include <linux/security.h>
#define PT_REGS_PARM3(x) ((x)->dx)

#define TASK_COMM_LEN 16
struct data_t {
   __u32 tgid;
   __u32 pid;
   __u32 uid;
   int cap;
   char comm[TASK_COMM_LEN];
};
#define MID_MAP_SIZE 4*1024*1024
#define MIN_MAP_SIZE 4*1024
#define bpfprint(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

struct{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
    __uint(max_entries, MIN_MAP_SIZE);
} events SEC(".maps");


SEC("kprobe/cap_capable")
int kprobe__cap_capable(struct pt_regs *ctx, const struct cred *cred,
    struct user_namespace *targ_ns, int cap, int cap_opt)
{
    __u64 __pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid = __pid_tgid >> 32;
    __u32 pid = __pid_tgid;
    __u32 uid = bpf_get_current_uid_gid();
    struct data_t data = {};
    data.tgid = tgid;
    data.pid = pid;
    data.uid = uid;
    data.cap = PT_REGS_PARM3(ctx);
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpfprint("pid:[%u] comm:[%s] CAP:[%d]", pid, data.comm, data.cap);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    return 0;
    
};
char _license[] SEC("license") = "GPL";