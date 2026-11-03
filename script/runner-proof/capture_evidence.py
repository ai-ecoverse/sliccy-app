from pathlib import Path
import os
import stat

PREFIXES = ('Sliccy-', 'ScreenProofSurface-', 'slicc-', 'Google Chrome-', 'nativeproof.test-')


def crash_directories():
    return [Path.home() / 'Library/Logs/DiagnosticReports', Path('/Library/Logs/DiagnosticReports')]


def eligible(path):
    return path.name.startswith(PREFIXES) and path.suffix in ('.ips', '.crash', '.diag')


def crash_baseline():
    result = {}
    for directory in crash_directories():
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('crash directory')
        for path in directory.iterdir():
            if eligible(path):
                info = path.lstat()
                result[str(path)] = (info.st_ino, info.st_size, info.st_mtime_ns)
    return result


def collect_crashes(baseline, evidence):
    destination = evidence / 'crashes'; destination.mkdir(mode=0o700)
    total, count = 0, 0
    for directory in crash_directories():
        if not directory.exists():
            continue
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError('crash directory')
        for path in directory.iterdir():
            if not eligible(path):
                continue
            info = path.lstat()
            if baseline.get(str(path)) == (info.st_ino, info.st_size, info.st_mtime_ns):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('crash file')
            total += info.st_size; count += 1
            if total > 16 * 1024 * 1024 or count > 64:
                raise ValueError('crash bound')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as source:
                current = os.fstat(source.fileno())
                if (current.st_ino, current.st_size, current.st_mtime_ns) != (info.st_ino, info.st_size, info.st_mtime_ns):
                    raise ValueError('crash changed')
                data = source.read(info.st_size + 1)
                if len(data) != info.st_size:
                    raise ValueError('crash changed')
            (destination / ('crash-%03d' % count + path.suffix)).write_bytes(data)
