struct sliccy_screen_process_identity {
    int32_t pid, parent;
    uint32_t uid;
    uint64_t seconds, microseconds;
};
int sliccy_runner_identity(pid_t pid, struct sliccy_screen_process_identity *identity) {
    if (!identity || pid <= 0) return EINVAL;
    struct proc_bsdinfo value = {0};
    errno = 0;
    int count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &value, sizeof(value));
    if (count < 0 || (size_t)count != sizeof(value)) return errno ? errno : EINVAL;
    if (value.pbi_pid != (uint32_t)pid || !value.pbi_start_tvsec || value.pbi_start_tvusec >= 1000000) return EINVAL;
    identity->pid = pid; identity->parent = value.pbi_ppid; identity->uid = value.pbi_uid;
    identity->seconds = value.pbi_start_tvsec; identity->microseconds = value.pbi_start_tvusec;
    return 0;
}
int sliccy_runner_path(pid_t pid, char *path, uint32_t size) {
    if (!path || size < PROC_PIDPATHINFO_MAXSIZE) return EINVAL;
    errno = 0;
    int count = proc_pidpath(pid, path, size);
    return count > 0 && (uint32_t)count < size ? 0 : (errno ? errno : EINVAL);
}
