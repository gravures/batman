#!/usr/bin/env python3
# Copyright (c) 2024 - Gilles Coissac
# This file is part of Batman program.
#
# Lyndows is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# Lyndows is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Lyndows. If not, see <https://www.gnu.org/licenses/>
from __future__ import annotations

import argparse
import os
import shutil
import sys
from dataclasses import dataclass
from enum import StrEnum, unique
from functools import partial
from pathlib import Path
from typing import Any
from warnings import warn

import tomli

from session import Session
from system import Command, format_bytes, get_mount_point


TMP = "/var/tmp"  # noqa: S108
RESTORE_DIR = "RESTORED"


@unique
class Backend(StrEnum):
    FILE = "file"
    FTP = "ftp"
    SFTP = "sftp"
    SCP = "scp"
    FISH = "fish"


class VolumeError(Exception):
    def __init__(self, msg: str) -> None:
        self.msg = msg
        super().__init__()


class VolumeNotFoundError(VolumeError):
    def __init__(self, vol: str) -> None:
        super().__init__(f"{vol} not found on the system")


class UnmountedVolumeError(VolumeError):
    def __init__(self, host: str) -> None:
        super().__init__(f"volume disk {host} is not mounted")


class UnpluggedVolumeError(VolumeError):
    def __init__(self, disk: str) -> None:
        super().__init__(f"Volume disk {disk} is not plugged in")


class WrongVolumeError(VolumeError):
    def __init__(self, vol: str) -> None:
        super().__init__(f"file {vol} should be a mount point")


class UnresolvedVoumeError(VolumeError):
    def __init__(self, vol: str) -> None:
        super().__init__(f"Unable to resolve {vol} to a valid disk device")


@dataclass(slots=True, kw_only=True, unsafe_hash=True)
class Volume:
    """A duplicity volume where backup will be stored."""

    scheme: Backend
    host: str
    path: str
    port: int | None = None
    user: str | None = None
    password: str | None = None

    @property
    def url(self) -> str:
        if self.scheme != Backend.FILE:
            psw = f":{self.password}" if self.password else ""
            user = f"{self.user}{psw}@" if self.user else ""
            port = f":{self.port}" if self.port else ""
            host = self.host
        else:
            port = user = ""
            host = self._resolve_file_host()

        return f"{self.scheme}://{user}{host}{port}/{self.path}"

    def url_as_path(self) -> str:
        return (
            f"{self._resolve_file_host()}/{self.path}" if self.scheme == Backend.FILE else self.url
        )

    def _resolve_file_host(self) -> str:
        if "/" in self.host:  # file system path
            host = Path(self.host).expanduser().absolute()
            if not host.exists():
                raise VolumeNotFoundError(self.host)
            if not host.is_mount():
                raise WrongVolumeError(self.host)
            if host.is_relative_to("/media"):
                warn(
                    f"{self.host} is defined as an automatic mounted point. "
                    "It will not be available with this path in a "
                    "recovery session (with a root loging).",
                    stacklevel=1,
                )
        else:  # disk label or uuid
            host = self.host
            for test_pth in (Path("/dev/disk/by-label"), Path("/dev/disk/by-uuid")):
                if (test_pth / host).exists():
                    dev = (test_pth / host).resolve()
                    host = get_mount_point(dev)
                    if not host:
                        # TODO: found but not mounted
                        # ..so mount it somewhere
                        raise UnmountedVolumeError(str(self.host))
                    break
            else:
                raise UnpluggedVolumeError(self.host)
        if not host:
            raise UnresolvedVoumeError(host)
        return str(host)

    def info(self) -> str:
        info = []
        try:
            url = self.url
        except VolumeError as e:
            info.append(f"Be aware: {e.msg}")
        else:
            info.append(f"volume url: {url}")

            if self.scheme == Backend.FILE:
                stat = shutil.disk_usage(self.url_as_path())
                info.extend((
                    f"volume host {self.host} is mounted",
                    (
                        f"disk usage : {format_bytes(stat.used)}/{format_bytes(stat.total)},"
                        f"free={format_bytes(stat.free)})"
                    ),
                ))
        info.append("------------------------------------------------------------")
        return "\n".join(info)


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
    keep_last_full: int

    @property
    def repository(self) -> str:
        return f"{self.volume.url}/{self.name.upper()}"

    def backup_args(
        self,
        archive: str | None,
        dryrun: bool = False,
        full: bool = False,
        progress: bool = False,
    ) -> list[str]:
        opts = [
            "full" if full else "incremental",
            f"--name={self.name}",
            f"--tempdir={TMP}",
            f"--log-file={self.volume.url_as_path()}/duplicity-{self.name.upper()}.log",
        ]

        if archive:
            opts.append(f"--archive-dir={archive}")
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

    def remove_old_args(self) -> list[str]:
        return ["remove-all-but-n-full", f"{self.keep_last_full}", "--force", self.repository]

    def status_args(self, archive: str | None) -> list[str]:
        # TODO: collection-status [--file-changed <relpath>] [--show-changes-in-set <index>]
        archive = f"--archive-dir={archive}" if archive else ""
        return [
            "collection-status",
            archive,
            f"--name={self.name}",
            self.repository,
        ]

    def list_files_args(self) -> list[str]:
        return ["duplicity", "list-current-files", self.repository]

    def restore_args(self, file: Path, restore: Path, archive: str | None) -> list[str]:
        archive = f"--archive-dir={archive}" if archive else ""
        return [
            archive,
            f"--name={self.name}",
            f"--tempdir={TMP}",
            f"--log-file={self.volume.url_as_path()}/duplicity-{self.name.upper()}.log",
            "--no-restore-ownership",
            f"--path-to-restore={file}",
            "restore",
            self.repository,
            str(restore),
        ]

    def __str__(self) -> str:
        r = f"Job definition for <{self.name}>: \nroot: {self.root}"
        if self.exclude:
            r += "\nexclude files : [%s]" % (", ".join(self.exclude))
        if self.prehook:
            r += "\njob with prehook"
        if self.keep_last_full:
            r += "\nremove old backup > %i" % self.keep_last_full
        return r


class Pool:
    """A container for Volumes."""

    __slots__ = ("volumes",)

    def __init__(self, mapping: dict[str, Any]) -> None:
        self.volumes: dict[str, Volume] = {}
        for name, vol_def in mapping.items():
            self.volumes[name] = Volume(
                scheme=vol_def["scheme"],
                host=vol_def["host"],
                path=vol_def["path"],
                port=vol_def.get("port"),
                user=vol_def.get("user"),
                password=vol_def.get("password"),
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
                        keep_last_full=job_def.get("keep_last_full", 0),
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

    def __init__(self, session: Session) -> None:
        self.session: Session = session
        self.duplicity = Command("duplicity", self.session.user)
        self.duplicity_env: dict[str, str] = os.environ.copy()

        config = Config()
        self.duplicity_archive_dir: str | None = config.read("batman/archive")

        if env := config.read("batman/env"):
            self.duplicity_env |= env

        self.pool = Pool(config.read("volumes"))
        self.session.log(*self.pool.info())

        self.queue = Queue(self.pool, config.read("jobs"))

        parser = self.parser()
        args = parser.parse_args()
        if hasattr(args, "func"):
            args.func(args)
        else:
            parser.print_help()

    def jobs_from_args(self, args: argparse.Namespace) -> list[Job]:
        return list(self.queue) if args.job == "all" else [self.queue.get(args.job)]

    def ensure_volume(self, job: Job) -> None:
        try:
            _ = job.volume.url
        except UnpluggedVolumeError:
            self.session.log(f"Please, attach backup volume {job.volume.host}, exiting...\n")
            self.session.exit(1)
        except VolumeError as e:
            self.session.log(e.msg)
            self.session.exit(1)

    def backup(self, args: argparse.Namespace) -> None:
        for job in self.jobs_from_args(args):
            self.ensure_volume(job)

            # FIXME: does not work anymore
            # repo = Path(job.repository)
            # if not repo.is_dir():
            #     repo.mkdir()

            # TODO: call prehook
            # if job.prehook:
            #     pass

            self.session.handle_task(
                task=self.duplicity,
                opts=job.backup_args(
                    dryrun=args.dryrun,
                    full=args.full,
                    progress=args.progress,
                    archive=self.duplicity_archive_dir,
                ),
                desc=f"Starting <{job.name}> backup: {job.root}",
                err=f"<{job.name}> backup failed for {job.root}",
                success=f"<{job.name}> backup sucessfull for {job.root}",
                dryrun=args.dryrun,
                cleanup=partial(self._cleanup, job, args.dryrun),
                capture=False,
                env=self.duplicity_env,
            )

            if not args.dryrun:
                self.remove_old(job)
        self.session.exit()

    def remove_old(self, job: Job) -> None:
        if job.keep_last_full:
            self.session.handle_task(
                task=self.duplicity,
                opts=job.remove_old_args(),
                desc=f"Removing old backup for {job.name.upper()} : {job.root}",
                success=f"Sucessfully removed old backup <{job.name}> for {job.root}",
                err=f"Removing old backup <{job.name}> failed for {job.root}",
                dryrun=False,
                env=self.duplicity_env,
            )

    def restore(self, args: argparse.Namespace) -> None:
        # sourcery skip: class-extract-method
        jobs = self.jobs_from_args(args)
        if len(jobs) != 1:
            self.session.log("You should specify only one Job for restoring a file.")
            self.session.exit(1)
        job = jobs[0]

        file = Path(args.file)
        if file.is_absolute():
            self.session.log(f"file argument should be a relative path not '{file}'")
            self.session.exit(1)

        self.ensure_volume(job)
        abs_file = (Path(job.root) / file).expanduser().absolute()

        if abs_file == Path(job.root):
            self.session.log(
                f"You're asking to restore all the backup's contents from job <{job.name}>"
            )
            accept = input("Are you sure you want to do that (y,n)? ")
            if accept not in ("y", "Y"):
                self.session.exit()
        else:
            print(f"You're asking to restore the backup's contents for '{abs_file}'")
            accept = input("Please confirm your request(y,n)? ")
            if accept not in ("y", "Y"):
                sys.exit()

        restore = Path(job.root).expanduser().absolute() / RESTORE_DIR
        if not restore.is_dir():
            restore.mkdir()
        restore = restore / file.name

        self.session.handle_task(
            task=self.duplicity,
            opts=job.restore_args(file, restore, archive=self.duplicity_archive_dir),
            desc=f"trying to restore '{abs_file}' from job <{job.name}>...",
            err=f"<{job.name}> file(s) restoration failed for {abs_file}",
            success=(
                f"<{job.name}> file(s) '{abs_file}' restoration sucessfull, "
                f"look into '{RESTORE_DIR}' folder"
            ),
            env=self.duplicity_env,
        )
        self.session.exit()

    def cleanup(self, args: argparse.Namespace) -> None:
        for job in self.jobs_from_args(args):
            self._cleanup(job, dryrun=args.dryrun)
        self.session.exit()

    def _cleanup(self, job: Job, dryrun: bool):
        self.ensure_volume(job)
        self.session.handle_task(
            task=self.duplicity,
            opts=job.cleanup_args(dryrun=dryrun),
            desc=f"Cleaning {job.name.upper()} backup : {job.root}",
            err=f"Cleaning <{job.name}> backup failed for {job.root}",
            success=f"<{job.name}> cleaned sucessfully for {job.root}",
            dryrun=dryrun,
            env=self.duplicity_env,
        )

    def list_jobs(self, args: argparse.Namespace) -> None:
        for job in self.queue:
            self.session.log(job, "\n")
        self.session.exit()

    def list_files(self, args: argparse.Namespace) -> None:
        jobs = self.jobs_from_args(args)
        if len(jobs) != 1:
            self.session.log("You should specify only one Job for listing files in a backup.")
            self.session.exit(1)
        job = jobs[0]

        self.ensure_volume(job)
        self.session.handle_task(
            task=self.duplicity,
            opts=job.list_files_args(),
            desc=f"List current files for {job.name.upper()} : \nroot : {job.root}",
            err="",
            success="",
        )
        self.session.exit()

    def verify(self, args: argparse.Namespace) -> None:
        self.session.log("verify command is not yet implemented.")
        self.session.exit(1)

    def status(self, args: argparse.Namespace) -> None:
        for job in self.jobs_from_args(args):
            self.session.handle_task(
                task=self.duplicity,
                opts=job.status_args(archive=self.duplicity_archive_dir),
                desc=f"Collection status for {job.name.upper()} : \nroot : {job.root}",
                err="",
                success="",
            )
        self.session.exit()

    def _duplicity(self, args: argparse.Namespace) -> None:
        print("Calling duplicity with args:", args.args)
        self.duplicity(*args.args, capture=False)
        self.session.exit()

    def show_man(self, args: argparse.Namespace) -> None:
        os.system("man duplicity")  # noqa: S605, S607

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
        restore.set_defaults(func=self.restore)

        # duplicity command
        _help = "run duplicity directly"
        duplicity = commands.add_parser(
            "duplicity",
            help=_help,
            description=_help,
            prefix_chars="#",
        )
        duplicity.add_argument(
            "args",
            help="duplicity positional arguments",
            nargs="*",
            default=["--help"],
            action="store",
        )
        duplicity.set_defaults(func=self._duplicity)

        # man commamnd
        _help = "show duplicity man page"
        man = commands.add_parser("man", help=_help, description=_help)
        man.set_defaults(func=self.show_man)

        return parser


if __name__ == "__main__":
    Batman(session=Session(main=__file__, as_root=False))
