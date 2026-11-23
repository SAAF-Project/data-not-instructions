"""Run the pinned offline checker against paths inside a caller checkout."""
import pathlib
import shlex
import subprocess
import sys


def targets(checkout, paths):
    root = pathlib.Path(checkout).resolve(strict=True)
    selected = shlex.split(paths)
    if not selected:
        raise ValueError('no scan paths supplied')
    resolved = []
    for value in selected:
        relative = pathlib.Path(value)
        if relative.is_absolute():
            raise ValueError('scan paths must be relative to caller checkout')
        target = (root / relative).resolve(strict=True)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise ValueError('scan target escapes caller checkout') from exc
        component = root
        for part in relative.parts:
            component = component / part
            if component.is_symlink():
                raise ValueError('symlink scan targets are not assessed')
        resolved.append(str(target))
    return resolved


def main(argv):
    if len(argv) != 2:
        print('usage: run_check.py CALLER_CHECKOUT PATHS', file=sys.stderr)
        return 2
    try:
        selected = targets(*argv)
    except (OSError, ValueError) as exc:
        print(f'check_prompts: NOT ASSESSED: {str(exc)!r}', file=sys.stderr)
        return 2
    checker = pathlib.Path(__file__).resolve().with_name('check_prompts.py')
    return subprocess.run([sys.executable, '-I', str(checker), *selected], cwd=checker.parent).returncode


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
