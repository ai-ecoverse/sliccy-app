import re


def exact_test_pattern(name):
    if not name or any(not part for part in name.split('/')):
        raise ValueError('exact-test-name')
    return '/'.join('^' + re.escape(part) + '$' for part in name.split('/'))


def runtime_result(result, name, assertion=None):
    if result is None or result.returncode != (1 if assertion is not None else 0):
        return False
    try:
        text = result.stdout.decode('utf-8', errors='strict')
        errors = result.stderr.decode('utf-8', errors='strict')
    except UnicodeError:
        return False
    if any(token in text + errors for token in ('panic:', 'fatal error:', 'runtime error:', '--- SKIP:')):
        return False
    if not re.search(r'^=== RUN   ' + re.escape(name) + r'$', text, re.MULTILINE):
        return False
    outcome = 'FAIL' if assertion is not None else 'PASS'
    if not re.search(r'^\s*--- ' + outcome + ': ' + re.escape(name) + r' \([0-9.]+s\)$', text, re.MULTILINE):
        return False
    if assertion is not None:
        return re.search(r'(?<![A-Za-z0-9_-])' + re.escape(assertion) + r'(?![A-Za-z0-9_-])', text) is not None
    return True


def suite_result(result, names):
    if result.returncode != 0 or not names or len(names) != len(set(names)):
        return False
    try:
        text = result.stdout.decode('utf-8', errors='strict')
        errors = result.stderr.decode('utf-8', errors='strict')
    except UnicodeError:
        return False
    if any(token in text + errors for token in ('panic:', 'fatal error:', 'runtime error:', '--- SKIP:')):
        return False
    started = re.findall(r'^=== RUN   ([^/\n]+)$', text, re.MULTILINE)
    passed = re.findall(r'^--- PASS: ([^/\n ]+) \([0-9.]+s\)$', text, re.MULTILINE)
    return sorted(started) == sorted(names) and sorted(passed) == sorted(names)
