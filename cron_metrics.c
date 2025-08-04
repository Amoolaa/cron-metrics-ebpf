//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define CMDLINE_MAX 128
#define MAX_ENTRIES_RINGBUF 10240
#define MAX_ENTRIES_RUNNING 10240
#define MAX_ENTRIES_COUNT 10240

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct cron_event {
    __u32 pid;
    __u32 ppid;
    __u64 start_time;
    __u64 duration;
    __s32 exit_code;
    char comm[TASK_COMM_LEN];
    char cmdline[CMDLINE_MAX];
};

// perf buffer for completed events
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} cron_events SEC(".maps");

// map tracking running cron jobs
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES_RUNNING);
    __type(key, __u32);
    __type(value, struct cron_event);
} cron_starts SEC(".maps");

// helper to detect if parent is cron daemon
// note: we're inlining for epbf reasons (instruction count limits, verifier, stack limit)
static __always_inline bool is_cron_child(struct task_struct *task) {
    struct task_struct *parent;
    char parent_comm[TASK_COMM_LEN];

    // use real_parent, see https://ypl.coffee/parent-and-real-parent-in-task-struct/
    parent = BPF_CORE_READ(task, real_parent);
    bpf_core_read_str(parent_comm, sizeof(parent_comm), &parent->comm);
    if (bpf_strncmp(parent_comm, 4, "cron") == 0 || bpf_strncmp(parent_comm, 5, "crond") == 0) {
        return true;
    }
    return false;
}

static __always_inline int read_cmdline(struct task_struct *task, char *cmdline, int max_len) {
    struct mm_struct *mm;
    unsigned long arg_start, arg_end;
    __u32 len = 0;

    mm = BPF_CORE_READ(task, mm);
    if (!mm) {
        return -1;
    }

    arg_start = BPF_CORE_READ(mm, arg_start);
    arg_end = BPF_CORE_READ(mm, arg_end);

    if (arg_start >= arg_end) {
        return -1;
    }

    len = arg_end - arg_start;
    if (len > max_len - 1) {
        len = max_len - 1;
    }

    long ret = bpf_probe_read_user(cmdline, len, (void *)arg_start);
    if (ret < 0) {
        return ret;
    }

    // argv is separated by null bytes
    for (int i = 0; i < len; i++) {
        if (cmdline[i] == '\0') {
            cmdline[i] = ' ';
        }
    }
    
    // ensure null termination
    cmdline[len] = '\0';
    return len;
}

SEC("tp/sched/sched_process_exec")
int trace_exec(struct trace_event_raw_sched_process_template *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!is_cron_child(task)) {
        return 0;
    }
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct cron_event event = {};

    event.pid = pid;
    event.ppid = BPF_CORE_READ(task, real_parent, pid);
    event.start_time = bpf_ktime_get_ns();
    if (bpf_get_current_comm(event.comm, sizeof(event.comm))) {
        bpf_printk("failed to get comm\n");
        return 0;
    }
    
    // read full cmdline
    int cmdline_len = read_cmdline(task, event.cmdline, sizeof(event.cmdline));
    if (cmdline_len < 0) {
        // fallback to command name if it fails
        bpf_probe_read_kernel_str(event.cmdline, sizeof(event.cmdline), event.comm);
    }

    // store start event
    if (bpf_map_update_elem(&cron_starts, &pid, &event, BPF_ANY) < 0) {
        bpf_printk("failed to store start event for PID %d\n", pid);
        return 0;
    }

    bpf_printk("cron job started: %s (PID: %d)\n", event.comm, pid);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int trace_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!is_cron_child(task)) {
        return 0;
    }

    // check if exited pid exists in map
    __u32 pid = ctx->pid;
    struct cron_event *start_event = bpf_map_lookup_elem(&cron_starts, &pid);
    if (!start_event) {
        bpf_printk("failed to lookup start event for PID %d\n", pid);
        return 0;
    }

    struct cron_event event = *start_event;
    event.duration = bpf_ktime_get_ns() - start_event->start_time;
    event.exit_code = BPF_CORE_READ(task, exit_code) >> 8;

    bpf_printk("cron job completed: %s (pid: %d, duration: %llu ns, exit: %d)\n", 
        event.comm, pid, event.duration, event.exit_code);

    // Send event to userspace via perf buffer
    bpf_perf_event_output(ctx, &cron_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// TODO
//
// sched_process_fork and cleaning up unused entries after a time period