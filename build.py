#!/usr/bin/env python3
# OpenWRT Declarative Image Builder
# https://github.com/gucci-on-fleek/openwrt-builder-template
# SPDX-License-Identifier: MPL-2.0+
# SPDX-FileCopyrightText: 2025 Max Chernoff

###############
### Imports ###
###############
import secrets
from argparse import ArgumentParser, FileType, RawDescriptionHelpFormatter
from base64 import b85decode, b85encode
from copy import copy as python_copy
from datetime import datetime
from io import BufferedReader
from os import chown, getenv
from pathlib import Path
from pprint import pprint
from re import MULTILINE
from re import sub as re_sub
from shutil import copy2 as file_copy
from sys import stdin, stdout
from time import sleep
from tomllib import load as load_toml
from typing import Iterable, Iterator, Self, TypeAlias, TypedDict, cast

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20
from deepmerge import always_merger
from lark import Lark, Transformer
from podman import PodmanClient

####################
### Type Aliases ###
####################
ConfigDict: TypeAlias = dict[str, str | list[str]]
PackageDict: TypeAlias = dict[str, list[ConfigDict] | dict[str, ConfigDict]]
UciDict: TypeAlias = dict[str, PackageDict]


class _Image(TypedDict):
    version: str
    target: str
    subtarget: str
    profile: str
    packages: list[str]


class _FilesFindReplace(TypedDict):
    path: str
    find: str
    replace: str


class _FilesContent(TypedDict):
    path: str
    content: str


class TomlDict(TypedDict):
    image: _Image
    files: list[_FilesFindReplace | _FilesContent]
    uci: UciDict


#################
### Constants ###
#################
UCI_GRAMMAR = r""" # The EBNF grammar for a UCI config file
    # Match the whole file
    uci: _NL? (package+ | (config*))

    # Each package begins with a header and includes configs
    package: "package" string _NL package_contents
    package_contents: config*

    # Each config begins with a header and includes options and lists
    config: "config" string string? _NL config_contents

    # Config contents
    config_contents: (option | list)*
    option: "option" string string _NL
    list: "list" string string _NL

    # All the string types
    string: _WS+ (_raw_string | escaped_string)+
    _raw_string: _single_string | _empty_string
    escaped_string: _double_string | _unquoted_string

    # String implementation
    _single_string: "'" /[^']+/ "'"
    _double_string: "\"" /[^"]+/ "\""
    _unquoted_string: /[^\s"'#\\]+/ | ESCAPED_CHAR
    ESCAPED_CHAR: ("\\" /./)+
    _empty_string: "\"\"" | "''"

    # Misc. Tokens
    _NL: /(\s*(#[^\n]*)?\r?\n)+\s*/
    %import common.WS_INLINE -> _WS
"""

NAME_BY_TYPE = ("system", "firewall")


#########################
### Class Definitions ###
#########################
class Crypto:
    """Encrypt and decrypt base-85 encoded strings using UNAUTHENTICATED
    symmetric encryption.
    """

    def __init__(self, key: str | None) -> None:
        if not isinstance(key, str):
            raise TypeError(f"Expected str, got {type(key)}")

        self.key = b85decode(key)

    def encrypt(self, data: str | bytes) -> str:
        """Encrypt a single string."""
        if isinstance(data, str):
            data = data.encode("ascii")

        nonce = secrets.token_bytes(16)
        cipher = Cipher(algorithm=ChaCha20(self.key, nonce), mode=None)
        encryptor = cipher.encryptor()
        ct = encryptor.update(data) + encryptor.finalize()
        return b85encode(nonce + ct).decode("ascii")

    def decrypt(self, data: str | bytes) -> bytes:
        """Decrypt a single string."""
        if isinstance(data, str):
            data = data.encode("ascii")

        decoded = b85decode(data)
        nonce, ct = decoded[:16], decoded[16:]
        cipher = Cipher(algorithm=ChaCha20(self.key, nonce), mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    def decrypt_all_inplace(self, data: dict | list) -> None:
        """Decrypt all encrypted strings in a dictionary or list."""

        iter: Iterable

        if isinstance(data, list):
            iter = enumerate(data)
        elif isinstance(data, dict):
            iter = data.items()
        else:
            raise TypeError(f"Expected list or dict, got {type(data)}")

        for key, value in iter:
            if isinstance(value, str) and value.startswith("ENC:"):
                data[key] = self.decrypt(value[4:])
            elif isinstance(value, bool):
                data[key] = "1" if (value == True) else "0"
            elif isinstance(value, (list, dict)):
                self.decrypt_all_inplace(value)


class Uci:
    """Parse and generate UCI config files."""

    class TreeToUci(Transformer):
        """Converts a Lark parse tree into a `UciDict`."""

        uci = dict
        package = tuple

        def package_contents(self, node) -> UciDict:
            out: UciDict = {}
            for item in node:
                try:
                    # See if we have a "_name" key
                    try:
                        name: str = item[1][0]["_name"]
                    except KeyError:
                        name = item[1][0]["name"]

                    name = name.replace("-", "_")

                    if " " in name:
                        raise KeyError

                    # Make sure that all previous items had "_name" keys
                    if isinstance(out.get(item[0]), list):
                        raise KeyError
                except (KeyError, TypeError, IndexError):  # Return a list
                    if isinstance(item[1], list):
                        out[item[0]] = (
                            cast(list, out.get(item[0], [])) + item[1]
                        )
                    else:
                        out[item[0]] = item[1]
                else:  # Return a dict
                    try:
                        del item[1][0]["_name"]
                    except KeyError:
                        pass
                    out[item[0]] = out.get(item[0], {})
                    cast(dict, out[item[0]])[name] = item[1][0]

            return out

        def config(self, node) -> tuple[str, list[ConfigDict]]:
            type = node[0]
            contents = node[-1]
            name = node[1]

            if name is not contents:
                contents["_name"] = name
            elif type in NAME_BY_TYPE:
                contents["_name"] = type

            return (type, [contents])

        config_contents = package_contents
        option = tuple

        def list(self, node) -> tuple[str, list[str]]:
            return (node[0], [node[1]])

        def string(self, node) -> str:
            return "".join(node)

        def escaped_string(self, node) -> str:
            return node[0].replace("\\", "")

    def __init__(self) -> None:
        """Initialize the parser and transformer."""

        self.parser = Lark(UCI_GRAMMAR, start="uci", parser="lalr", strict=True)
        self.transformer = self.TreeToUci()
        self._data: UciDict = {}

    def __ior__(self, other: UciDict) -> Self:
        """Merge or store the parsed UCI data."""
        if len(self._data) == 0:
            self._data = other
        else:
            self._data = always_merger.merge(self._data, other)

        return self

    def __iter__(self) -> Iterator[tuple[str, Self]]:
        """Iterate over the packages."""
        for package, data in self._data.items():
            new = python_copy(self)
            new._data = {package: data}
            yield (package, new)

    def in_uci(self, text: str, package: str | None = None) -> None:
        """Parse a UCI config file."""
        if package:
            text = f"package {package}\n{text}"

        tree = self.parser.parse(text)
        parsed: UciDict = self.transformer.transform(tree)
        self |= parsed

    def in_toml(
        self, file: BufferedReader, crypto: Crypto | None = None
    ) -> TomlDict:
        """Parse a TOML file and decrypt any encrypted strings."""
        toml = cast(TomlDict, load_toml(file))

        if crypto:
            crypto.decrypt_all_inplace(toml)  # type: ignore

        uci = toml["uci"]

        self |= uci

        return toml

    def out_batch(self) -> str:
        """Converts a dictionary into a UCI batch string."""
        out: list[str] = []

        out.append("#!/bin/sh")
        out.append("uci -q batch <<EOF")

        for package, data in self._data.items():
            for type, data in data.items():
                assert isinstance(data, dict)
                for name, config in data.items():
                    fqn = f"{package}.{name}"

                    out.append(f"set {fqn}={type}")

                    for key, value in config.items():
                        if isinstance(value, list):
                            for item in value:
                                if isinstance(item, bytes):
                                    item = item.decode("utf-8")
                                if item == "_delete":
                                    out.append(f"delete {fqn}.{key}")
                                else:
                                    out.append(f"add_list {fqn}.{key}='{item}'")
                        else:
                            if isinstance(value, bytes):
                                value = value.decode("utf-8")
                            out.append(f"set {fqn}.{key}='{value}'")

                    out.append("")

        out.append("commit")
        out.append("EOF")
        out.append("exit 0")

        return "\n".join(out)

    def out_uci(self) -> str:
        """Converts a dictionary into a UCI config string."""
        out: list[str] = []

        for package, data in self._data.items():
            if len(self._data) > 1:
                out.append(f"package {package}")
                out.append("")

            for type, data in data.items():
                for val in data:
                    if isinstance(data, dict) and isinstance(val, str):
                        name = val
                        config = data[val]
                    elif isinstance(data, list) and isinstance(val, dict):
                        config = val
                        name = cast(str | None, config.get("_name"))
                    else:
                        raise TypeError

                    if name:
                        out.append(f"config {type} '{name}'")
                    else:
                        out.append(f"config {type}")

                    for key, value in config.items():
                        if isinstance(value, list):
                            for i, item in enumerate(value):
                                if item == "_delete":
                                    value = value[i + 1 :]
                            for item in value:
                                if isinstance(item, bytes):
                                    item = item.decode("utf-8")
                                out.append(f"\tlist {key} '{item}'")
                        else:
                            if isinstance(value, bytes):
                                value = value.decode("utf-8")
                            out.append(f"\toption {key} '{value}'")

                    out.append("")

        return "\n".join(out)


def process_uci(
    uci_data: UciDict,
    container_root: Path,
    uid: int,
    gid: int,
) -> None:
    """Process the UCI data and write it to the container."""

    uci = Uci()
    for file in (container_root / "etc/config").iterdir():
        with file.open("rt") as f:
            uci.in_uci(f.read(), file.stem)

    uci |= uci_data

    for package, data in uci:
        path = container_root / f"etc/config/{package}"

        if path.is_file():
            with path.open("wt") as f:
                f.write(data.out_uci())
        else:
            path = container_root / f"etc/uci-defaults/98-{package}"

            with path.open("wt") as f:
                f.write(data.out_batch())

        chown(path, uid, gid)


def process_files(
    files: list[_FilesFindReplace | _FilesContent],
    container_root: Path,
    uid: int,
    gid: int,
) -> None:
    """Process the files and write them to the container."""

    for file in files:
        path = container_root / file["path"].removeprefix("/")

        for parent in reversed(path.parents):
            if not parent.is_dir():
                parent.mkdir()
                chown(parent, uid, gid)

        if "find" in file:
            with path.open("rt") as f:
                contents = f.read()

            find = file["find"]
            if isinstance(find, bytes):
                find = find.decode("utf-8")

            replace = file["replace"]
            if isinstance(replace, bytes):
                replace = replace.decode("utf-8")

            contents = re_sub(find, replace, contents, flags=MULTILINE)

            with path.open("wt") as f:
                f.write(contents)
        else:
            with path.open("wb") as f:
                contents = file["content"]
                if isinstance(contents, str):
                    contents = contents.encode("utf-8")
                f.write(contents)

        chown(path, uid, gid)


def build(config: TomlDict) -> None:
    """Builds the OpenWRT image."""
    config_image = config["image"]

    with PodmanClient() as podman:
        assert podman.version()

        image = podman.images.pull(
            "ghcr.io/openwrt/imagebuilder",
            f"{config_image['target']}-"
            f"{config_image['subtarget']}-"
            f"{config_image['version']}",
        )

        assert not isinstance(image, Iterable)

        container = podman.containers.run(
            image=image,
            entrypoint=["/bin/bash"],
            command=[
                "-c",
                "./setup.sh &&"
                + " make image"
                + f" PROFILE='{config_image["profile"]}'"
                + f" PACKAGES='{" ".join(config_image["packages"])}'"
                + " clean_ipkg='kill -SIGSTOP -1'",
            ],
            init=True,
            detach=True,
        )

        assert not isinstance(container, Iterable)

        for _ in range(300):
            for state in container.top(ps_args="state", stream=True):
                assert isinstance(state, dict)

                if any(filter(lambda x: x == ["T"], state["Processes"])):
                    break
            else:
                sleep(1)
                continue
            break
        else:
            raise RuntimeError("Build never paused")

        root = Path(container.inspect()["Mounts"][0]["Source"])
        container_root = next(root.glob("build_dir/target-*/root-*"))
        perm_source = (container_root / "etc/openwrt_release").stat()

        process_uci(
            config["uci"],
            container_root,
            perm_source.st_uid,
            perm_source.st_gid,
        )

        process_files(
            config["files"],
            container_root,
            perm_source.st_uid,
            perm_source.st_gid,
        )

        container.exec_run(["/bin/bash", "-c", "kill -SIGCONT -1"])
        container.wait()

        date_str = datetime.now().strftime("%F_%H%M")

        bin = next(root.glob("bin/targets/*/*/*-squashfs-sysupgrade.bin"))
        file_copy(bin, f"{config_image['profile']}-{date_str}.bin")

        container.remove(v=True, force=True)


def process_cmdline(filename: BufferedReader, crypto: Crypto) -> None:
    """Parse the command line arguments and process the file."""
    uci = Uci()
    config = uci.in_toml(filename, crypto)
    build(config)


def cmdline_string(arg: str) -> str | bytes:
    """Handles processing a string from the command line."""
    if arg == "-":
        return stdin.buffer.read().strip()
    else:
        return arg


if __name__ == "__main__":
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        epilog="""environment variables:
  $OPENWRT_KEY          The key to use for encryption""",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-e", "--encrypt", type=str, metavar="text", help="Encrypt a string"
    )
    group.add_argument(
        "-d", "--decrypt", type=str, metavar="text", help="Decrypt a string"
    )
    group.add_argument(
        "--keygen", action="store_true", help="Generate a new key"
    )
    group.add_argument(
        "filename",
        type=FileType("rb"),
        nargs="?",
        help="The config file to build",
    )

    args = vars(parser.parse_args())
    try:
        crypto = Crypto(getenv("OPENWRT_KEY"))
    except TypeError:
        crypto = None

    match [args, crypto]:
        case [{"encrypt": str(encrypt)}, Crypto as crypto]:
            encrypt = cmdline_string(encrypt)
            print("ENC:", crypto.encrypt(encrypt), sep="")

        case [{"decrypt": str(decrypt)}, Crypto as crypto]:
            input = cmdline_string(decrypt)
            output = crypto.decrypt(input[4:])
            stdout.buffer.write(output + b"\n")

        case [{"keygen": True}, _]:
            print(b85encode(secrets.token_bytes(32)).decode("ascii"))

        case [{"filename": filename}, Crypto as crypto]:
            process_cmdline(filename, crypto)

        case _:
            print("! Invalid arguments or environment variables.\n")
            parser.print_help()

            exit(1)
