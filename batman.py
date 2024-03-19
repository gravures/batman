#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass
import os
import pwd
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

import tomli


ARCHIVE_DIRECTORY = "/archive/duplicity"
TMP = "/var/tmp"  # noqa: S108
RESTORE_DIR = "RESTORED"


def bootstrap():
    sudo_user()


def sudo_user():
    if not shutil.which("sudo"):
        os.system("su -c apt-get install sudo")  # noqa: S605, S607
    user = os.getlogin()
    os.system(f"su -c /sbin/usermod -aG sudo {user}")  # noqa: S605


def format_bytes(
    nbytes: int, unit: str | None = None, suffix: str = "b", space: bool = True
) -> str:
    """Format bytes size.

    Scale bytes to its proper byte format.
    e.g: 1253656678 => '1.17GB'

    Args:
        nbytes (int): bytes size to format.
        unit (str | None): unit to convert bytes,
        if None unit will be search for best fit.
        suffix (str): Letter added just after the
        main unit letter (Mb, Kb, etc).Defaults to "b".
        space (bool): add space before the unit letter.
        Defaults to True.

    Returns:
        str: formated string.
    """
    units = ["B", "K", "M", "G", "T", "P", "E", "Z"]
    factor = 1024
    space = " " if space else ""  # type: ignore

    if unit:
        if unit not in units:
            raise ValueError(f"unit {unit} shold be one of {units}")
        res = nbytes if unit == "B" else nbytes / factor ** (units.index(unit))
        return f"{res:.2f}{space}{unit}{suffix}"

    units[0] = ""
    for unit in units:
        if nbytes < factor:
            return f"{nbytes:.2f}{space}{unit}{suffix}"
        nbytes /= factor  # type: ignore

    return f"{nbytes:.2f}{space}Y{suffix}"


class Command:
    """Command class."""

    class Error(Exception):
        def __init__(self, msg: str, retcode: int = 0, cmd: list[str] | None = None) -> None:
            if retcode and cmd:
                _cmd = " ".join(cmd)
                msg = f"command <{_cmd}> returned non-zero exit status {retcode}.\n{msg}"
                self.returncode = retcode
            self.msg = msg
            super().__init__(msg)

    def __init__(self, name: str, user: str, path: os.PathLike | None = None) -> None:
        if path is None:
            self.command = shutil.which(name)
        else:
            _path = Path(path)
            self.command = path if _path.is_file() else None
        if self.command is None:
            raise Command.Error(f"Command {path or name} not found on your system.")
        self.user: str = user
        self.name: str = name

    def _create_exception(self) -> type:
        return type(f"{self.name.capitalize()}Error", (Command.Error,), {})

    def _run(self, *args: str, user: str, capture: bool = True, **kwargs) -> str:
        """Run the command and return stdout."""
        _args = ["sudo", "-u", user]

        if kwargs.get("env") is not None:
            _env = ",".join(kwargs["env"].keys())
            _args.append(f"--preserve-env={_env}")

        _args.append(self.command)  # type: ignore
        _args.extend(args)

        cp = subprocess.run(
            _args,
            capture_output=capture,
            shell=False,  # noqa: S603
            check=False,
            encoding="UTF-8",
            text=True,
            **kwargs,
        )
        if cp.returncode:
            raise self._create_exception()(cp.stderr, cp.returncode, _args)
        return cp.stdout or ""

    def __call__(self, *args: str, user: str | None = None, capture: bool = True, **kwargs) -> str:
        _user = user or self.user
        return self._run(*args, user=_user, capture=capture, **kwargs)


@dataclass(frozen=True, kw_only=True, slots=True)
class Volume:
    """A duplicity volume where backup will be stored."""

    kind: str
    url: str

    def is_available(self) -> bool:
        return os.path.ismount(self.url)

    def info(self) -> str:
        if self.is_available():
            stat = shutil.disk_usage(self.url)
            return (
                f"\nvolume {self.url} is mounted"
                f"disk usage : {format_bytes(stat.used)}/{format_bytes(stat.total)}, "
                f"free={format_bytes(stat.free)})"
                "------------------------------------------------------------\n"
            )
        return (
            f"\nBe aware that volume {self.url} is not mounted\n"
            "------------------------------------------------------------\n"
        )


@dataclass(slots=True, kw_only=True, unsafe_hash=True)
class Job:
    """Represent a backup job."""

    name: str
    root: Path
    volume: Volume
    exclude: tuple[str, ...]
    exclude_ofs: bool
    full_delay: str
    prehook: os.PathLike | None
    remove_old: int
    repository: str = field(init=False, compare=False)

    def __post_init__(self) -> None:
        self.repository = f"{self.volume.kind}://{self.volume.url}/{self.name.upper()}"

    def backup_args(
        self, dryrun: bool = False, full: bool = False, progress: bool = False
    ) -> list[str]:
        opts = [
            "full" if full else "incremental",
            f"--archive-dir={ARCHIVE_DIRECTORY}",
            f"--name={self.name}",
            f"--tempdir={TMP}",
            f"--log-file={self.volume.kind}://{self.volume.url}/duplicity-{self.name.upper()}.log",
        ]

        if self.exclude:
            opts.extend(f"--exclude={filepath}" for filepath in self.exclude)
        if self.exclude_ofs:
            opts.append("--exclude-other-filesystems")
        if self.full_delay:
            opts.append(f"--full-if-older-than={self.full_delay}")
        if dryrun:
            opts.append("--dry-run")
        if progress:
            opts.append("--progress")

        opts.extend((str(self.root), self.repository))
        return opts

    def cleanup_args(self, dryrun: bool = False) -> list[str]:
        opts = ["cleanup"]
        if not dryrun:
            opts.append("--force")
        opts.append(self.repository)
        return opts

    def remove_old_args(self, num: int) -> list[str]:
        return ["remove-all-but-n-full", f"{num}", "--force", self.repository]

    def status_arsg(self) -> list[str]:
        # TODO: collection-status [--file-changed <relpath>] [--show-changes-in-set <index>]
        return [
            "collection-status",
            f"--archive-dir={ARCHIVE_DIRECTORY}",
            f"--name={self.name}",
            self.repository,
        ]

    def list_files_args(self) -> list[str]:
        return ["duplicity", "list-current-files", self.repository]

    def restore_args(self, file: Path, restore: Path) -> list[str]:
        return [
            f"--archive-dir={ARCHIVE_DIRECTORY}",
            f"--name={self.name}",
            f"--tempdir={TMP}",
            f"--log-file={self.repository}/duplicity-{self.name.upper()}.log",
            "restore",
            f"--file-to-restore={file}",
            "--do-not-restore-ownership",
            self.repository,
            str(restore),
        ]

    def __str__(self) -> str:
        r = f"Job definition for <{self.name}>: \nroot: {self.root}"
        if self.exclude:
            r += "\nexclude files : [%s]" % (", ".join(self.exclude))
        if self.prehook:
            r += "\njob with prehook"
        if self.remove_old:
            r += "\nremove old backup > %i" % self.remove_old
        return r


class Pool:
    """A container for Volumes."""

    __slots__ = ("volumes",)

    def __init__(self, mapping: dict[str, Any]) -> None:
        self.volumes: dict[str, Volume] = {}
        for name, vol_def in mapping.items():
            self.volumes[name] = Volume(
                kind=vol_def["type"],
                url=vol_def["url"],
            )

    def info(self) -> tuple[str, ...]:
        out = [vol.info() for vol in self.volumes.values()]
        return tuple(out)

    def get(self, name: str) -> Volume:
        return self.volumes[name]


class Queue:
    """A container for Jobs."""

    __slots__ = ("jobs", "pool")

    def __init__(self, pool: Pool, mapping: dict[str, Any] | None = None) -> None:
        self.jobs: set[Job] = set()
        self.pool = pool
        if mapping:
            for name, job_def in mapping.items():
                self.jobs.add(
                    Job(
                        name=name,
                        root=job_def["root"],
                        volume=self.pool.get(job_def["volume"]),
                        exclude=tuple(job_def.get("exclude", [])),
                        exclude_ofs=job_def.get("exclude_ofs", False),
                        full_delay=job_def.get("full_delay", ""),
                        remove_old=job_def.get("remove_old", 1),
                        prehook=None,
                    )
                )

    def add(self, job: Job) -> None:
        self.jobs.add(job)

    def get(self, name: str) -> Job:
        for job in self.jobs:
            if job.name == name:
                return job
        raise LookupError(
            f"<{name}> is not a valid job name, registered jobs: {[j.name for j in self.jobs]}"
        )

    def __iter__(self):
        yield from self.jobs

    def __len__(self) -> int:
        return len(self.jobs)


class Config:
    def __init__(self) -> None:
        path = Path.home() / ".config/batman/batman.toml"
        self.mapping: dict[str, Any] = {}
        with path.open(mode="r") as stream:
            try:
                self.mapping = tomli.loads(stream.read())
            except Exception:
                print(f"Loading {path} failed!")

    def read(self, path: str) -> Any:
        """Looks for property in config."""
        _path = path.split("/")
        config = self.mapping
        for entry in _path[:-1]:
            config = config.get(entry, None)
            if config is None:
                return None
        return config.get(_path[-1], None)


class Batman:
    """Backup Application."""

    def __init__(self) -> None:
        user: str = self.check_user()

        self.duplicity = Command("duplicity", user)

        config = Config()
        if passphrase := config.read("batman/passphrase"):
            os.putenv("PASSPHRASE", passphrase)

        self.pool = Pool(config.read("volumes"))
        self.log(*self.pool.info())

        self.queue = Queue(self.pool, config.read("jobs"))

        parser = self.parser()
        args = parser.parse_args()
        if hasattr(args, "func"):
            args.func(args)
        else:
            parser.print_help()

    def check_user(self) -> str:
        # print(
        #     f"login: {os.getlogin()}, user: {getpass.getuser()},
        #               uidd: {os.getuid()}, home: {Path.home()}"
        # )
        if os.getlogin() == "root":
            if os.getuid() != 0:
                return self.get_username(os.getuid())
            self.log("You are in a root session (maybe in a system rescue boot mode).")
            self.fork()
        elif getpass.getuser() == "root" or os.getuid() == 0:
            self.log("batman should not be run as root! aborting...")
            self.exit(1)
        return os.getlogin()

    def fork(self):
        users = self.get_users()
        if len(users) > 0:
            choices = ", ".join([f"as {u}[{i}]" for i, u in enumerate(users)])
            valid = (str(i) for i in range(len(users)))
            out = input(f"Choose if you want to login {choices} or aborting[any key]: ")
            if out in valid:
                user = users[int(out)]
                self.exit(os.system(f"sudo -u {user} python3 {__file__}"))  # noqa: S605
            else:
                self.log("Aborting...")
                self.exit(0)
        else:
            self.log("No valid login user were found on this system, exiting...")
            self.exit(1)

    def get_username(self, uid: int) -> str:
        return pwd.getpwuid(uid).pw_name

    def get_users(self) -> list[str]:
        with Path("/etc/login.defs").open("r") as lgn:
            if sch := re.search(r"^UID_MIN\s+(\d+)", lgn.read()):
                min_uid = int(sch[1])
            else:
                min_uid = 1000

        return [
            p.pw_name
            for p in pwd.getpwall()
            if (
                p.pw_uid >= min_uid
                and p.pw_shell not in ("/usr/sbin/nologin", "/bin/false")
                and p.pw_dir.startswith("/home")
            )
        ]

    def exit(self, code: int = 0) -> None:
        sys.exit(code)

    def log(self, *args: Any) -> None:
        for st in args:
            if st:
                print(st)

    def elapse(self, from_time: float) -> None:
        t = time.strftime("%H:%M:%S", time.gmtime(time.time() - from_time))
        self.log(f"Temps écoulé : {t}\n")

    def jobs_from_args(self, args: argparse.Namespace) -> list[Job]:
        return list(self.queue) if args.job == "all" else [self.queue.get(args.job)]

    def ensure_volume(self, job: Job) -> None:
        if not job.volume.is_available():
            self.log(f"Please, attach backup volume {job.volume.url}, exiting...\n")
            self.exit(1)

    def handle_task(
        self,
        task: Command,
        opts: list[str],
        desc: str,
        success: str,
        err: str,
        dryrun: bool = False,
        cleanup: partial[None] | None = None,
    ) -> None:
        self.log("\n")
        self.log(desc)
        if dryrun:
            self.log("running in dry-run mode")
        try:
            start = time.time()
            out = task(*opts)
        except Command.Error as e:
            self.log("********************************")
            self.log(err)
            self.log(e.msg)
            if cleanup:
                cleanup()
        else:
            self.log(success)
            self.log(out)
            self.elapse(start)
        finally:
            pass

    def backup(self, args: argparse.Namespace) -> None:
        for job in self.jobs_from_args(args):
            self.ensure_volume(job)

            repo = Path(job.repository)
            if not repo.is_dir():
                repo.mkdir()

            if job.prehook:
                pass

            self.handle_task(
                task=self.duplicity,
                opts=job.backup_args(dryrun=args.dryrun, full=args.full, progress=args.progress),
                desc=f"Starting <{job.name}> backup: {job.root}",
                err=f"<{job.name}> backup failed for {job.root}",
                success=f"<{job.name}> backup sucessfull for {job.root}",
                dryrun=args.dryrun,
                cleanup=partial(self._cleanup, job, args.dryrun),
            )

            if job.remove_old and not args.dryrun:
                self.remove_old(job, num=job.remove_old)
        self.exit()

    def remove_old(self, job: Job, num: int = 1) -> None:
        self.handle_task(
            task=self.duplicity,
            opts=job.remove_old_args(num),
            desc=f"Removing old backup for {job.name.upper()} : {job.root}",
            success=f"Sucessfully removed old backup <{job.name}> for {job.root}",
            err=f"Removing old backup <{job.name}> failed for {job.root}",
            dryrun=False,
        )

    def restore(self, args: argparse.Namespace) -> None:
        # sourcery skip: class-extract-method
        jobs = self.jobs_from_args(args)
        if len(jobs) != 1:
            self.log("You should specify only one Job for restoring a file.")
            self.exit(1)
        job = jobs[0]

        file = Path(args.file)
        if file.is_absolute():
            self.log(f"file argument should be a relative path not '{file}'")
            self.exit(1)

        self.ensure_volume(job)
        abs_file = (Path(job.root) / file).expanduser().absolute()

        if abs_file == Path(job.root):
            self.log(f"You're asking to restore all the backup's contents from job <{job.name}>")
            accept = input("Are you sure you want to do that (y,n)? ")
            if accept not in ("y", "Y"):
                self.exit()
        else:
            print(f"You're asking to restore the backup's contents for '{abs_file}'")
            accept = input("Please confirm your request(y,n)? ")
            if accept not in ("y", "Y"):
                sys.exit()

        restore = Path(job.root).expanduser().absolute() / RESTORE_DIR
        if not restore.is_dir():
            restore.mkdir()
        restore = restore / file.name

        self.handle_task(
            task=self.duplicity,
            opts=job.restore_args(file, restore),
            desc=f"trying to restore '{abs_file}' from job <{job.name}>...",
            err=f"<{job.name}> file(s) restoration failed for {abs_file}",
            success=(
                f"<{job.name}> file(s) '{abs_file}' restoration sucessfull, "
                "look into '{RESTORE_DIR}' folder"
            ),
        )
        self.exit()

    def cleanup(self, args: argparse.Namespace) -> None:
        for job in self.jobs_from_args(args):
            self._cleanup(job, dryrun=args.dryrun)
        self.exit()

    def _cleanup(self, job: Job, dryrun: bool):
        self.ensure_volume(job)
        self.handle_task(
            task=self.duplicity,
            opts=job.cleanup_args(dryrun=dryrun),
            desc=f"Cleaning {job.name.upper()} backup : {job.root}",
            err=f"Cleaning <{job.name}> backup failed for {job.root}",
            success=f"<{job.name}> cleaned sucessfully for {job.root}",
            dryrun=dryrun,
        )

    def list_jobs(self, args: argparse.Namespace) -> None:
        for job in self.queue:
            self.log(job, "\n")
        self.exit()

    def list_files(self, args: argparse.Namespace) -> None:
        jobs = self.jobs_from_args(args)
        if len(jobs) != 1:
            self.log("You should specify only one Job for listing files in a backup.")
            self.exit(1)
        job = jobs[0]

        self.ensure_volume(job)
        self.handle_task(
            task=self.duplicity,
            opts=job.list_files_args(),
            desc=f"List current files for {job.name.upper()} : \nroot : {job.root}",
            err="",
            success="",
        )
        self.exit()

    def verify(self, args: argparse.Namespace) -> None:
        self.log("verify command is not yet implemented.")
        self.exit(1)

    def status(self, args: argparse.Namespace) -> None:
        for job in self.jobs_from_args(args):
            self.handle_task(
                task=self.duplicity,
                opts=job.status_arsg(),
                desc=f"Collection status for {job.name.upper()} : \nroot : {job.root}",
                err="",
                success="",
            )
        self.exit()

    def parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="batman",
            description="Personnal backup utility using duplicity",
        )

        jobs_parser = argparse.ArgumentParser(add_help=False)
        jobs_parser.add_argument(
            "job",
            help="the job's name the command will refer to (default to all jobs)",
            action="store",
            nargs="?",
            choices=([j.name for j in self.queue]).append("all"),
            default="all",
        )

        dryrun_parser = argparse.ArgumentParser(add_help=False, parents=[jobs_parser])
        dryrun_parser.add_argument(
            "-d",
            "--dryrun",
            dest="dryrun",
            action="store_true",
            help="run in dry run mode",
        )

        commands = parser.add_subparsers()

        # list command
        _help = "list all known defined jobs"
        _list = commands.add_parser("list", help=_help, description=_help)
        _list.set_defaults(func=self.list_jobs)

        # status command
        _help = "summarize the status of the backup repository for specified jobs"
        status = commands.add_parser(
            "status", parents=[jobs_parser], help=_help, description=_help
        )
        status.set_defaults(func=self.status)

        # backup command
        _help = "launch backup for specified jobs"
        backup = commands.add_parser(
            "backup", parents=[dryrun_parser], help=_help, description=_help
        )
        backup.add_argument(
            "-f",
            "--full",
            dest="full",
            action="store_true",
            help="perform a full backup, even if the full delay for a job is not reach",
        )
        backup.add_argument(
            "-p",
            "--progress",
            dest="progress",
            action="store_true",
            help="print a backup progress when possible",
        )
        backup.set_defaults(func=self.backup)

        # verify command
        _help = "actually not yet implemented"
        verify = commands.add_parser("verify", help=_help, description=_help)
        verify.set_defaults(func=self.verify)

        # cleanup command
        _help = (
            "clean up the backup repository for specified jobs from extraneous "
            "duplicity files in case of a backup session failed"
        )
        cleanup = commands.add_parser(
            "cleanup", parents=[dryrun_parser], help=_help, description=_help
        )
        cleanup.set_defaults(func=self.cleanup)

        # list-files command
        _help = "lists the files contained in the most current backup for specified jobs"
        list_files = commands.add_parser(
            "files", parents=[jobs_parser], help=_help, description=_help
        )
        list_files.set_defaults(func=self.list_files)

        # restore command
        _help = "restore the full monty or selected folders/files"
        restore = commands.add_parser(
            "restore", parents=[jobs_parser], help=_help, description=_help
        )
        restore.add_argument(
            "file",
            help="a file path relative to the job's root (default will restore all the job)",
            default=".",
            action="store",
            nargs="?",
        )
        restore.set_defaults(
            func=self.restore, parents=[jobs_parser], help=_help, description=_help
        )

        return parser


if __name__ == "__main__":
    Batman()
