
from pathlib import Path
import json
import os
import platform
import plistlib
import stat
import subprocess

RECEIPT = 'com.apple.pkg.RosettaUpdateAuto'
RUNTIME = Path('/Library/Apple/usr/libexec/oah/libRosettaRuntime')


def require_host(env, system, machine, version):
    required = {'GITHUB_ACTIONS': 'true', 'GITHUB_REPOSITORY': 'ai-ecoverse/sliccy-app',
                'GITHUB_EVENT_NAME': 'workflow_dispatch',
                'GITHUB_REF': 'refs/heads/proof/runner-capture-v1',
                'SLICCY_RUNNER_ENVIRONMENT': 'github-hosted'}
    if any(env.get(key) != value for key, value in required.items()):
        raise ValueError('host gate')
    if system != 'Darwin' or machine != 'arm64' or version.split('.')[0] != '27':
        raise ValueError('platform gate')


def decide(receipt_ok, runtime_regular, runtime_apple_signed):
    ready = receipt_ok and runtime_regular and runtime_apple_signed
    return {'schema': 1, 'macAppRosettaEstablished': ready,
            'receiptPresent': receipt_ok, 'conventionalMacRuntimeRegular': runtime_regular,
            'conventionalMacRuntimeAppleSigned': runtime_apple_signed,
            'translatedLaunchAttempted': False, 'installerAttempted': False,
            'linuxVMRuntimeUsedAsEvidence': False,
            'outcome': 'PREFLIGHT_READY' if ready else 'FAILED_TO_DEMONSTRATE'}


def inspect():

    require_host(os.environ, platform.system(), platform.machine(), platform.mac_ver()[0])
    receipt_ok = runtime_regular = runtime_signed = False
    clean_env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LANG': 'C'}
    try:
        receipt = subprocess.run(['/usr/sbin/pkgutil', '--pkg-info-plist', RECEIPT],
                                 stdin=subprocess.DEVNULL, capture_output=True, timeout=5, env=clean_env)
        if receipt.returncode == 0 and len(receipt.stdout) <= 65536:
            info = plistlib.loads(receipt.stdout)
            receipt_ok = isinstance(info, dict) and info.get('pkgid') == RECEIPT and isinstance(info.get('pkg-version'), str) and bool(info['pkg-version'])
    except (OSError, subprocess.TimeoutExpired, ValueError, plistlib.InvalidFileException):
        pass
    try:
        info = RUNTIME.lstat()
        runtime_regular = stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_size > 0
        if runtime_regular:
            checked = subprocess.run(['/usr/bin/codesign', '--verify', '--strict', '-R', '=anchor apple', str(RUNTIME)],
                                     stdin=subprocess.DEVNULL, capture_output=True, timeout=5, env=clean_env)
            runtime_signed = checked.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        pass
    return decide(receipt_ok, runtime_regular, runtime_signed)
