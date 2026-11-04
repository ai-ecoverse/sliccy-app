#include <assert.h>
#include "prerequisite_launch_boundary.h"

int main(void) {
    struct sliccy_prerequisite_launch value;
    const char *good[] = {"probe", "5", "42"};
    assert(sliccy_prerequisite_launch_arguments(3, good, &value) == 0);
    const char *expected[] = {"/usr/bin/sudo", "-n", "--preserve-env=GITHUB_ACTIONS,GITHUB_EVENT_NAME,GITHUB_REF,GITHUB_REPOSITORY,SLICCY_RUNNER_ENVIRONMENT", "--", "/Library/SliccyProof-5/Sliccy.app/Contents/MacOS/Sliccy", "--runner-kernel", "42"};
    for (int i = 0; i < 7; i++) assert(strcmp(value.arguments[i], expected[i]) == 0);
    assert(value.arguments[7] == NULL && value.target_pid == 42);
    const char *environment[] = {"GITHUB_ACTIONS=true", "GITHUB_EVENT_NAME=workflow_dispatch", "GITHUB_REF=refs/heads/proof/runner-capture-v1", "GITHUB_REPOSITORY=ai-ecoverse/sliccy-app", "SLICCY_RUNNER_ENVIRONMENT=github-hosted"};
    for (int i = 0; i < 5; i++) assert(strcmp(value.environment[i], environment[i]) == 0);
    assert(value.environment[5] == NULL);
    const char *invalid[] = {"", "0", "01", "-1", "+1", "1/../../x", " 1", "1 ", "1\n", "--path", "/tmp/app", "18446744073709551616", "999999999999999999999999"};
    for (size_t i = 0; i < sizeof(invalid)/sizeof(invalid[0]); i++) {
        const char *run[] = {"probe", invalid[i], "42"};
        const char *target[] = {"probe", "5", invalid[i]};
        assert(sliccy_prerequisite_launch_arguments(3, run, &value) != 0);
        assert(sliccy_prerequisite_launch_arguments(3, target, &value) != 0);
    }
    const char *large_target[] = {"probe", "5", "2147483648"};
    assert(sliccy_prerequisite_launch_arguments(3, large_target, &value) != 0);
    const char *max[] = {"probe", "18446744073709551615", "2147483647"};
    assert(sliccy_prerequisite_launch_arguments(3, max, &value) == 0);
    assert(strcmp(value.arguments[4], "/Library/SliccyProof-18446744073709551615/Sliccy.app/Contents/MacOS/Sliccy") == 0);
    assert(sliccy_prerequisite_launch_arguments(2, good, &value) != 0);
    const char *extra[] = {"probe", "5", "42", "--override"};
    assert(sliccy_prerequisite_launch_arguments(4, extra, &value) != 0);
    puts("synthetic actual launch boundary PASS");
    return 0;
}
