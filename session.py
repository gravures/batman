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
import pwd
import re
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

from system import Command


if TYPE_CHECKING:
    from functools import partial


class Session:
    def __init__(self, main: str, as_root: bool) -> None:
        self.as_root: bool = as_root
        self.main: str = main
        self._user: str = self.check_user()

    @property
    def user(self) -> str:
        return self._user

    def handle_task(
        self,
        task: Command,
        opts: list[str],
        desc: str,
        success: str,
        err: str,
        dryrun: bool = False,
        cleanup: partial[None] | None = None,
        **kwargs: Any,
    ) -> None:
        self.log("\n")
        self.log(desc)
        if dryrun:
            self.log("running in dry-run mode")
            self.log(f"command: {task.name} {opts} {kwargs}")
        try:
            start = time.time()
            out = task(*opts, **kwargs)
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

    def elapse(self, from_time: float) -> None:
        t = time.strftime("%H:%M:%S", time.gmtime(time.time() - from_time))
        self.log(f"Temps écoulé : {t}\n")

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
            if not self.as_root:
                self.log("This program is not intended to be run as root! aborting...")
                self.exit(1)
        return os.getlogin()

    @staticmethod
    def log(*args: Any) -> None:
        for st in args:
            if st:
                print(st)

    @staticmethod
    def exit(code: int = 0) -> NoReturn:
        sys.exit(code)

    @staticmethod
    def get_username(uid: int) -> str:
        return pwd.getpwuid(uid).pw_name

    @staticmethod
    def get_real_users() -> list[str]:
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

    def fork(self) -> NoReturn:
        users = Session.get_real_users()
        if len(users) > 0:
            choices = ", ".join([f"as {u}[{i}]" for i, u in enumerate(users)])
            valid = (str(i) for i in range(len(users)))
            out = input(f"Choose if you want to login {choices} or aborting[any key]: ")
            if out in valid:
                user = users[int(out)]
                Session.exit(os.system(f"sudo -u {user} python3 {self.main}"))  # noqa: S605
            else:
                Session.log("Aborting...")
                Session.exit(0)
        else:
            Session.log("No valid login user were found on this system, exiting...")
            Session.exit(1)


# def bootstrap():
#     sudo_user()


# def sudo_user():
#     if not shutil.which("sudo"):
#         os.system("su -c apt-get install sudo")
#     user = os.getlogin()
#     os.system(f"su -c /sbin/usermod -aG sudo {user}")
