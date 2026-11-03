#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
probe_root=$(mktemp -d /private/tmp/sliccy-socket-probe.XXXXXX)
trap 'rm -rf "$probe_root"' EXIT
/usr/bin/xcrun clang -Wall -Wextra -Werror -I Sources/ScreenSystem/include \
  Sources/ScreenSystem/ScreenSystem.c Tests/NativeScreenFilterProbe/socket-tests.c \
  -framework Security -framework CoreFoundation -o "$probe_root/socket-tests"
/usr/bin/xcrun clang -Wall -Wextra -Werror Tests/NativeScreenFilterProbe/exec-layout-test.c -o "$probe_root/exec-layout-test"
"$probe_root/socket-tests" "$probe_root/exec-layout-test"
/usr/bin/xcrun clang -Wall -Wextra -Werror Tests/NativeScreenFilterProbe/exec-lane-tests.c -o "$probe_root/exec-lane-tests"
"$probe_root/exec-lane-tests"
/usr/bin/xcrun clang -Wall -Wextra -Werror -I Sources/ScreenSystem/include \
  Sources/ScreenSystem/ScreenSystem.c Tests/NativeScreenFilterProbe/handoff-helper.c \
  -framework Security -framework CoreFoundation -o "$probe_root/handoff-helper"
/usr/bin/xcrun clang -Wall -Wextra -Werror -I Sources/ScreenSystem/include \
  Sources/ScreenSystem/ScreenSystem.c Tests/NativeScreenFilterProbe/handoff-tests.c \
  -framework Security -framework CoreFoundation -o "$probe_root/handoff-tests"
"$probe_root/handoff-tests" "$probe_root/handoff-helper"
