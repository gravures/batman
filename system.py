# Copyright (c) 2024 - Gilles Coissac
# This file is part of Batman program.
#
# Batman is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# Batman is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Batman. If not, see <https://www.gnu.org/licenses/>
from __future__ import annotations

import getpass
import os
import shutil
import subprocess
from pathlib import Path


class Command:
    """System command class."""

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


def get_mount_point(device: Path) -> str:
    df = Command("df", getpass.getuser())
    return next(
        (
            dev.split()[1].strip()
            for dev in df("-l", "--output=source,target").split(os.linesep)[1:]
            if dev.startswith(str(device))
        ),
        "",
    )


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
