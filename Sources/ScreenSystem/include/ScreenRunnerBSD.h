#ifndef SLICCY_RUNNER_BSD_H
#define SLICCY_RUNNER_BSD_H
#if defined(SLICCY_CAPTURE_RUNNER_PROOF)
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
struct sliccy_runner_bsd_value {
    int32_t pid, parent;
    uint32_t effective_uid, real_uid, saved_uid;
    uint64_t seconds, microseconds;
};
struct sliccy_runner_bsd_read {
    int32_t status;
    size_t count, expected;
    struct sliccy_runner_bsd_value value;
};
struct sliccy_runner_bsd_bracket {
    struct sliccy_runner_bsd_read before, proc, after;
};
struct sliccy_runner_bsd_observation {
    int32_t self_pid, parent_pid;
    struct sliccy_runner_bsd_bracket controls[2], target;
};
static inline int sliccy_bsd_valid(struct sliccy_runner_bsd_read r, int32_t pid) {
    return r.status == 0 && r.expected > 0 && r.count == r.expected && pid > 0 &&
        r.value.pid == pid && r.value.parent >= 0 && r.value.seconds > 0 && r.value.microseconds < 1000000;
}
static inline int sliccy_bsd_equal(struct sliccy_runner_bsd_value a, struct sliccy_runner_bsd_value b) {
    return a.pid == b.pid && a.parent == b.parent && a.effective_uid == b.effective_uid &&
        a.real_uid == b.real_uid && a.saved_uid == b.saved_uid && a.seconds == b.seconds && a.microseconds == b.microseconds;
}
static inline int sliccy_bsd_control(struct sliccy_runner_bsd_bracket b, int32_t pid) {
    return sliccy_bsd_valid(b.before, pid) && sliccy_bsd_valid(b.proc, pid) && sliccy_bsd_valid(b.after, pid) &&
        sliccy_bsd_equal(b.before.value, b.proc.value) && sliccy_bsd_equal(b.after.value, b.proc.value);
}
static inline int sliccy_bsd_controls(struct sliccy_runner_bsd_observation o) {
    return o.self_pid > 0 && o.parent_pid > 0 && o.self_pid != o.parent_pid &&
        sliccy_bsd_control(o.controls[0], o.self_pid) && sliccy_bsd_control(o.controls[1], o.parent_pid) &&
        o.controls[0].proc.value.parent == o.parent_pid;
}
static inline int sliccy_bsd_select(struct sliccy_runner_bsd_observation o, int32_t pid,
                                  struct sliccy_runner_bsd_value *value, int *used_sysctl) {
    if (!value || !used_sysctl || pid <= 0) return EINVAL;
    struct sliccy_runner_bsd_bracket b = o.target;
    if (!sliccy_bsd_valid(b.before, pid) || !sliccy_bsd_valid(b.after, pid) ||
        !sliccy_bsd_equal(b.before.value, b.after.value)) return EINVAL;
    if (b.proc.status == 0) {
        if (!sliccy_bsd_valid(b.proc, pid) || !sliccy_bsd_equal(b.before.value, b.proc.value)) return EINVAL;
        *value = b.proc.value; *used_sysctl = 0; return 0;
    }
    if (b.proc.status != EPERM || b.proc.count != 0 || !sliccy_bsd_controls(o)) return EACCES;
    *value = b.before.value; *used_sysctl = 1; return 0;
}
static inline int sliccy_bsd_windowserver(struct sliccy_runner_bsd_value a, struct sliccy_runner_bsd_value b) {
    return sliccy_bsd_equal(a, b) && a.pid > 0 && a.parent == 1 && a.effective_uid == 88 &&
        a.real_uid == 0 && a.saved_uid == 0 && a.seconds > 0 && a.microseconds < 1000000;
}
int sliccy_runner_bsd_observe(int32_t pid, struct sliccy_runner_bsd_observation *value);
int sliccy_runner_bsd_select(const struct sliccy_runner_bsd_observation *observation, int32_t pid,
                            struct sliccy_runner_bsd_value *value, int *used_sysctl);
int sliccy_runner_bsd_windowserver(const struct sliccy_runner_bsd_value *a, const struct sliccy_runner_bsd_value *b);
#endif
#endif
