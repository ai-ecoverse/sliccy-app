"""Assemble hosted mutation plans without Swift/Go compile or any subprocess."""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import io
import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Driver harness lives beside the app owner storage; next driver synthetic uses this worktree.
DRIVER_HARNESS = Path(__file__).resolve().parents[3] / 'v84-harness-worktree' / 'Tests' / 'DriverSchema6'


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def broken_build17_module_plan_access(root: Path = ROOT):
    """Reproduce the 7e8ad813 wiring mistake: Build16 module has no PLAN."""
    build16 = _load(root / 'Tests/RunnerBuild16/hosted.py', 'dry_run_build16_broken')
    return build16.PLAN  # AttributeError on the reviewed failure


def assemble_build17_plan(root: Path = ROOT):
    """Import RunnerBuild17/hosted.py and return the slice harness PLAN it extends."""
    module = _load(root / 'Tests/RunnerBuild17/hosted.py', 'dry_run_build17_hosted')
    # Correct wiring: PLAN lives on the inner slice harness.
    plan = module.harness.PLAN
    if not isinstance(plan, list) or not plan:
        raise AssertionError('build17-hosted-plan-empty')
    return plan


def check_swift_plan(root: Path, plan):
    names = []
    for row in plan:
        if len(row) != 5:
            raise AssertionError('build17-hosted-plan-row')
        name, relative, old, new, selected = row
        if name in names:
            raise AssertionError('build17-hosted-plan-duplicate:' + name)
        names.append(name)
        text = (root / relative).read_text()
        if text.count(old) != 1:
            raise AssertionError(f'build17-hosted-old-string:{name}:{text.count(old)}')
        if old == new:
            raise AssertionError('build17-hosted-noop:' + name)
        if not selected:
            raise AssertionError('build17-hosted-selected:' + name)
    return names


def assemble_driver_plan(harness_root: Path = DRIVER_HARNESS):
    """
    Driver hosted.py has no PLAN attribute; its mutation plan is mutants.json.
    Parse hosted.py (no exec of its env/Go body) and require the mutants.json load path.
    """
    hosted = (harness_root / 'hosted.py').read_text()
    tree = ast.parse(hosted)
    text = hosted
    if 'mutants.json' not in text:
        raise AssertionError('driver-hosted-missing-mutants-json')
    # Confirm the file loads mutants.json into all_mutations without needing env.
    loads_mutants = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'loads':
            loads_mutants = True
    if not loads_mutants:
        raise AssertionError('driver-hosted-missing-json-loads')
    mutants = json.loads((harness_root / 'mutants.json').read_text())
    if not isinstance(mutants, list) or not mutants:
        raise AssertionError('driver-mutants-empty')
    return mutants


def check_driver_plan(harness_root: Path, mutants):
    tar_path = harness_root / 'inputs' / 'driver-source.tar.gz'
    texts = {}
    with tarfile.open(tar_path) as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith('.go'):
                texts[member.name] = tar.extractfile(member).read().decode()
    names = []
    for mutant in mutants:
        name = mutant['name']
        if name in names:
            raise AssertionError('driver-mutant-duplicate:' + name)
        names.append(name)
        file = mutant['file']
        old = mutant['old']
        if file not in texts:
            raise AssertionError('driver-mutant-missing-file:' + file)
        if texts[file].count(old) != 1:
            raise AssertionError(f'driver-mutant-old-string:{name}:{texts[file].count(old)}')
    return names


def run(root: Path = ROOT, harness_root: Path = DRIVER_HARNESS, *, require_driver: bool = False):
    """Pure dry-run: assemble every next-run hosted plan; no Swift/Go/subprocess."""
    # Red on the 7e8ad813 module.PLAN mistake.
    try:
        broken_build17_module_plan_access(root)
    except AttributeError:
        broken_rejected = True
    else:
        broken_rejected = False
    if not broken_rejected:
        raise AssertionError('build17-broken-module-plan-not-rejected')

    app_plan = assemble_build17_plan(root)
    app_names = check_swift_plan(root, app_plan)
    report = {
        'brokenModulePlanRejected': True,
        'build17PlanCount': len(app_names),
        'build17PlanNames': app_names,
        'scope': 'pure import/AST/tar text; no Swift/Go/subprocess',
    }
    if harness_root.is_dir():
        driver_plan = assemble_driver_plan(harness_root)
        driver_names = check_driver_plan(harness_root, driver_plan)
        report['driverMutantCount'] = len(driver_names)
        report['driverMutantNames'] = driver_names
        report['driverHarness'] = str(harness_root)
    elif require_driver:
        raise AssertionError('driver-harness-required:' + str(harness_root))
    else:
        report['driverSkipped'] = 'harness-absent'
    return report


if __name__ == '__main__':
    report = run()
    print(json.dumps({k: report[k] for k in report if k not in ('build17PlanNames', 'driverMutantNames')}, indent=2))
    print('build17PlanNames', len(report['build17PlanNames']))
    print('driverMutantNames', len(report['driverMutantNames']))
