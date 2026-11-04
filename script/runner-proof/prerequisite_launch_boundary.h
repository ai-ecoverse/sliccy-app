#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct sliccy_prerequisite_launch {
    char run[21];
    char target[11];
    char executable[128];
    int32_t target_pid;
    char *arguments[8];
    char *environment[6];
};
static int sliccy_prerequisite_launch_arguments(int argc, const char **argv, struct sliccy_prerequisite_launch *value) {
    if (!value || !argv || argc != 3 || !argv[1] || !argv[2]) return EINVAL;
    if (!argv[1][0] || !argv[2][0] || strlen(argv[1]) > 20 || strlen(argv[2]) > 10) return EINVAL;
    for (int i = 1; i <= 2; i++) {
        if (argv[i][0] < '1' || argv[i][0] > '9') return EINVAL;
        for (const char *p = argv[i]; *p; p++) if (*p < '0' || *p > '9') return EINVAL;
    }
    errno = 0;
    unsigned long long run = strtoull(argv[1], NULL, 10);
    if (errno || !run || run > UINT64_MAX) return EINVAL;
    errno = 0;
    unsigned long target = strtoul(argv[2], NULL, 10);
    if (errno || !target || target > INT32_MAX) return EINVAL;
    memset(value, 0, sizeof(*value));
    snprintf(value->run, sizeof(value->run), "%llu", run);
    snprintf(value->target, sizeof(value->target), "%lu", target);
    if (strcmp(value->run, argv[1]) || strcmp(value->target, argv[2])) return EINVAL;
    int length = snprintf(value->executable, sizeof(value->executable), "/Library/SliccyProof-%s/Sliccy.app/Contents/MacOS/Sliccy", value->run);
    if (length <= 0 || (size_t)length >= sizeof(value->executable)) return EINVAL;
    value->target_pid = (int32_t)target;
    value->arguments[0] = "/usr/bin/sudo";
    value->arguments[1] = "-n";
    value->arguments[2] = "--preserve-env=GITHUB_ACTIONS,GITHUB_EVENT_NAME,GITHUB_REF,GITHUB_REPOSITORY,SLICCY_RUNNER_ENVIRONMENT";
    value->arguments[3] = "--";
    value->arguments[4] = value->executable;
    value->arguments[5] = "--runner-kernel";
    value->arguments[6] = value->target;
    value->environment[0] = "GITHUB_ACTIONS=true";
    value->environment[1] = "GITHUB_EVENT_NAME=workflow_dispatch";
    value->environment[2] = "GITHUB_REF=refs/heads/proof/runner-capture-v1";
    value->environment[3] = "GITHUB_REPOSITORY=ai-ecoverse/sliccy-app";
    value->environment[4] = "SLICCY_RUNNER_ENVIRONMENT=github-hosted";
    return 0;
}
