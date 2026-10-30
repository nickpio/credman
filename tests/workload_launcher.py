"""Trusted Linux rootless worker launcher. No request-selected commands or identity.

Supervisor contract: launch this file with a connected AF_UNIX SOCK_STREAM FD in
pass_fds, --channel-fd N, --worker PATH and --scratch-parent TASK_OWNED_DIR.
Worker is snapshotted read-only. Default worker kind is a Python script; use
--kind executable for a self-contained native executable using system libraries.
Worker sees the channel at fd3, stdin=/dev/null, and supervisor-supplied stdout /
stderr (use private pipes or /dev/null, never secret-bearing files). No other FDs
are intentionally inherited. fd3 possession binds a workload, not an LLM label.
"""
import argparse
import ctypes
import errno
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import sysconfig
import tempfile


class Refused(Exception):
    pass


def harden():
    libc = ctypes.CDLL(None, use_errno=True)
    # Linux PR_SET_NO_NEW_PRIVS and PR_SET_DUMPABLE. No privileged fallback.
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(4, 0, 0, 0, 0) != 0:
        raise Refused()


def close_extra_fds():
    # Enumeration happens before exec in a fresh, single-threaded helper.
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd > 2:
            try:
                os.close(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise Refused()


def checked_channel(fd):
    if fd < 3:
        raise Refused()
    duplicate = socket.socket(fileno=os.dup(fd))
    try:
        if duplicate.family != socket.AF_UNIX or duplicate.type != socket.SOCK_STREAM:
            raise Refused()
        duplicate.getpeername()
    finally:
        duplicate.close()


def runtime_mounts(interpreter):
    # Public dynamic-loader/Python runtime only, never /usr as a whole or HOME.
    mounts = []
    seen = set()
    for candidate in ['/usr/lib', '/usr/lib64', '/usr/local/lib', '/lib', '/lib64', sysconfig.get_path('stdlib')]:
        path = Path(candidate)
        if not path.is_absolute() or not path.exists():
            continue
        if not str(path.resolve()).startswith(('/usr/lib', '/usr/local/lib')):
            raise Refused()
        if str(path) not in seen:
            mounts += ['--ro-bind', str(path.resolve()), str(path)]
            seen.add(str(path))
    mounts += ['--ro-bind', str(interpreter), '/runtime/python']
    return mounts


def exec_sandbox(args):
    checked_channel(args.channel_fd)
    harden()
    # Bubblewrap has no preserve-fds option here. Carry the channel through
    # stdin, then remap it to fd3 in the sandbox's trusted bootstrap.
    os.dup2(args.channel_fd, 0, inheritable=True)
    close_extra_fds()
    interpreter = Path(sys.executable).resolve()
    command = [args.bwrap, '--die-with-parent', '--new-session',
               '--unshare-user', '--unshare-pid', '--unshare-net',
               '--unshare-ipc', '--unshare-uts', '--unshare-cgroup',
               '--disable-userns', '--assert-userns-disabled', '--cap-drop', 'ALL',
               '--clearenv', '--tmpfs', '/', '--proc', '/proc', '--dev', '/dev',
               '--dir', '/runtime', '--dir', '/program', '--dir', '/home/worker',
               '--tmpfs', '/scratch', '--chmod', '0700', '/scratch',
               '--setenv', 'HOME', '/home/worker', '--setenv', 'TMPDIR', '/scratch',
               '--setenv', 'LANG', 'C.UTF-8', '--chdir', '/scratch']
    command += runtime_mounts(interpreter)
    command += ['--ro-bind', args.snapshot, '/program', '--remount-ro', '/',
                '--', '/runtime/python',
                '-I', '-B', '/program/launcher.py', '--_worker', args.kind]
    # No inherited display/bus/auth/config environment even during bwrap setup.
    os.execve(args.bwrap, command, {'LANG': 'C.UTF-8'})


def exec_worker(kind):
    harden()
    status = Path('/proc/self/status').read_text()
    fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    if int(fields['CapEff'].strip(), 16) or fields['NoNewPrivs'].strip() != '1':
        raise Refused()
    channel = socket.socket(fileno=os.dup(0))
    try:
        if channel.family != socket.AF_UNIX or channel.type != socket.SOCK_STREAM:
            raise Refused()
        channel.getpeername()
        os.dup2(channel.fileno(), 3, inheritable=True)
        os.set_inheritable(3, True)
        # channel's duplicate can be fd3 itself. Detach so closing cannot close fd3.
        if channel.fileno() == 3:
            channel.detach()
    finally:
        channel.close()
    null = os.open('/dev/null', os.O_RDONLY)
    os.dup2(null, 0, inheritable=True)
    if null > 3:
        os.close(null)
    # Only fd3 survives, in addition to sanitized stdio.
    for name in os.listdir('/proc/self/fd'):
        fd = int(name)
        if fd > 3:
            try:
                os.close(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise Refused()
    worker_environment = {'HOME': '/home/worker', 'TMPDIR': '/scratch', 'LANG': 'C.UTF-8'}
    if kind == 'script':
        os.execve('/runtime/python', ['/runtime/python', '-I', '-B', '/program/worker'], worker_environment)
    elif kind == 'executable':
        os.execve('/program/worker', ['/program/worker'], worker_environment)
    raise Refused()


def launch(args):
    checked_channel(args.channel_fd)
    worker = Path(args.worker).resolve(strict=True)
    parent = Path(args.scratch_parent).resolve(strict=True)
    bwrap = Path(args.bwrap)
    if not bwrap.is_absolute() or not bwrap.is_file() or not os.access(bwrap, os.X_OK):
        raise Refused()
    if not worker.is_file() or not parent.is_dir():
        raise Refused()
    # This Bubblewrap needs /tmp before child mount setup, even with TMPDIR.
    # Supervisor provisions it in its own namespace. Never create/repair it here.
    if not Path('/tmp').is_dir():
        raise Refused()
    metadata = parent.stat()
    if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise Refused()
    with tempfile.TemporaryDirectory(prefix='credman-worker-', dir=parent) as temporary:
        snapshot = Path(temporary)
        shutil.copyfile(worker, snapshot / 'worker')
        shutil.copyfile(Path(__file__).resolve(), snapshot / 'launcher.py')
        (snapshot / 'worker').chmod(0o500 if args.kind == 'executable' else 0o400)
        (snapshot / 'launcher.py').chmod(0o400)
        command = [sys.executable, '-I', '-B', str(snapshot / 'launcher.py'), '--_exec',
                   '--snapshot', str(snapshot), '--bwrap', str(bwrap),
                   '--channel-fd', str(args.channel_fd), '--kind', args.kind]
        result = subprocess.run(command, pass_fds=(args.channel_fd,), close_fds=True,
                                stdin=subprocess.DEVNULL, env={'LANG': 'C.UTF-8'},
                                timeout=args.timeout)
        return result.returncode


def main():
    # Internal modes are trusted bootstrap machinery, not an authentication API.
    if len(sys.argv) == 3 and sys.argv[1] == '--_worker':
        exec_worker(sys.argv[2])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--channel-fd', type=int, required=True)
    parser.add_argument('--kind', choices=['script', 'executable'], default='script')
    parser.add_argument('--bwrap', default='/usr/bin/bwrap')
    parser.add_argument('--worker')
    parser.add_argument('--scratch-parent')
    parser.add_argument('--timeout', type=float, default=15)
    parser.add_argument('--_exec', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--snapshot', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args._exec:
        exec_sandbox(args)
    if not args.worker or not args.scratch_parent or not (0 < args.timeout <= 300):
        raise Refused()
    return launch(args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Refused, OSError, ValueError, KeyError, subprocess.SubprocessError):
        # Never stringify arguments, paths, requests, OS exceptions or responses.
        print('WORKLOAD_REFUSED', file=sys.stderr)
        raise SystemExit(125)
