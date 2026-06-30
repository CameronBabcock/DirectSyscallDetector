#
# Nirvana v2: Electric Boogaloo
# Return-provenance detection for raw and gadgeted direct syscalls.
#
# Project: DirectSyscallDetector
# Copyright 2026 Cameron Babcock
#
# Author / Researcher: Cameron Babcock
# GitHub: https://github.com/CameronBabcock
# Email: Cameron@CameronBabcock.net
# LinkedIn: https://www.linkedin.com/in/cameronbabcock/
#
# Licensed under the Apache License, Version 2.0. See LICENSE and NOTICE.
# For EDR, CNO, pentest agent work, endpoint security, Windows internals,
# or detection engineering work,
# please contact Cameron Babcock using the email or LinkedIn profile above.
#

from __future__ import annotations

"""Generate compile-checked PHNT signature metadata for exported syscall stubs.

Runtime still recovers syscall IDs from the loaded OS DLLs. This script only
turns PHNT prototypes into typed printers so the demo can explain recovered IDs
without maintaining a hand-written syscall-signature table.
"""

import argparse
import glob
import os
import re
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path


PHNT_VERSION = 117
PHNT_CONSTANTS = {
    "PHNT_MODE_KERNEL": 0,
    "PHNT_MODE_USER": 1,
    "PHNT_MODE": 1,
    "PHNT_WINDOWS_ANCIENT": 0,
    "PHNT_WINDOWS_XP": 51,
    "PHNT_WINDOWS_SERVER_2003": 52,
    "PHNT_WINDOWS_VISTA": 60,
    "PHNT_WINDOWS_7": 61,
    "PHNT_WINDOWS_8": 62,
    "PHNT_WINDOWS_8_1": 63,
    "PHNT_WINDOWS_10": 100,
    "PHNT_WINDOWS_10_TH2": 101,
    "PHNT_WINDOWS_10_RS1": 102,
    "PHNT_WINDOWS_10_RS2": 103,
    "PHNT_WINDOWS_10_RS3": 104,
    "PHNT_WINDOWS_10_RS4": 105,
    "PHNT_WINDOWS_10_RS5": 106,
    "PHNT_WINDOWS_10_19H1": 107,
    "PHNT_WINDOWS_10_19H2": 108,
    "PHNT_WINDOWS_10_20H1": 109,
    "PHNT_WINDOWS_10_20H2": 110,
    "PHNT_WINDOWS_10_21H1": 111,
    "PHNT_WINDOWS_10_21H2": 112,
    "PHNT_WINDOWS_10_22H2": 113,
    "PHNT_WINDOWS_11": 114,
    "PHNT_WINDOWS_11_22H2": 115,
    "PHNT_WINDOWS_11_23H2": 116,
    "PHNT_WINDOWS_11_24H2": 117,
    "PHNT_WINDOWS_11_25H2": 117,
    "PHNT_WINDOWS_NEW": 0xFFFFFFFF,
    "PHNT_VERSION": PHNT_VERSION,
}

PHNT_HEADER_NAMES = [
    "ntkeapi.h",
    "ntldr.h",
    "ntexapi.h",
    "ntmmapi.h",
    "ntobapi.h",
    "ntpsapi.h",
    "ntbcd.h",
    "ntdbg.h",
    "ntimage.h",
    "ntioapi.h",
    "ntlpcapi.h",
    "ntmisc.h",
    "ntpfapi.h",
    "ntpnpapi.h",
    "ntpoapi.h",
    "ntregapi.h",
    "ntrtl.h",
    "ntsam.h",
    "ntseapi.h",
    "nttmapi.h",
    "nttp.h",
    "ntuser.h",
    "ntwmi.h",
    "ntwow64.h",
    "ntxcapi.h",
]


@dataclass(frozen=True)
class Prototype:
    name: str
    argument_names: tuple[str, ...]
    argument_type_names: tuple[str, ...]


@dataclass(frozen=True)
class SignatureEntry:
    export_name: str
    type_source_name: str
    argument_names: tuple[str, ...]
    argument_type_names: tuple[str, ...]


def evaluate_condition(expression: str) -> bool:
    prepared = expression.strip()
    prepared = re.sub(
        r"defined\s*\(\s*([A-Za-z_]\w*)\s*\)",
        lambda match: "1" if match.group(1) in PHNT_CONSTANTS else "0",
        prepared,
    )
    prepared = re.sub(
        r"defined\s+([A-Za-z_]\w*)",
        lambda match: "1" if match.group(1) in PHNT_CONSTANTS else "0",
        prepared,
    )
    prepared = prepared.replace("&&", " and ")
    prepared = prepared.replace("||", " or ")
    prepared = re.sub(r"!\s*(?!=)", " not ", prepared)

    def replace_identifier(match: re.Match[str]) -> str:
        if match.group(0) in {"and", "or", "not"}:
            return match.group(0)
        value = PHNT_CONSTANTS.get(match.group(0), 0)
        return str(value)

    prepared = re.sub(r"\b[A-Za-z_]\w*\b", replace_identifier, prepared)
    if re.search(r"[^0-9xXa-fA-F<>=!()+\-*/% \tandor]", prepared):
        return False

    try:
        return bool(eval(prepared, {"__builtins__": {}}, {}))
    except (SyntaxError, NameError, ValueError, ZeroDivisionError):
        return False


def filter_active_lines(text: str) -> str:
    active_stack = [True]
    branch_stack: list[tuple[bool, bool]] = []
    output: list[str] = []

    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped.startswith("#"):
            if active_stack[-1]:
                output.append(line)
            continue

        directive_match = re.match(r"#\s*(\w+)(.*)", stripped)
        if directive_match is None:
            continue

        directive = directive_match.group(1)
        rest = directive_match.group(2).strip()

        if directive == "if":
            parent_active = active_stack[-1]
            condition_active = evaluate_condition(rest)
            branch_stack.append((parent_active, condition_active))
            active_stack.append(parent_active and condition_active)
        elif directive == "ifdef":
            parent_active = active_stack[-1]
            condition_active = rest in PHNT_CONSTANTS
            branch_stack.append((parent_active, condition_active))
            active_stack.append(parent_active and condition_active)
        elif directive == "ifndef":
            parent_active = active_stack[-1]
            condition_active = rest not in PHNT_CONSTANTS
            branch_stack.append((parent_active, condition_active))
            active_stack.append(parent_active and condition_active)
        elif directive == "elif" and branch_stack:
            parent_active, branch_taken = branch_stack[-1]
            condition_active = (not branch_taken) and evaluate_condition(rest)
            branch_stack[-1] = (parent_active, branch_taken or condition_active)
            active_stack[-1] = parent_active and condition_active
        elif directive == "else" and branch_stack:
            parent_active, branch_taken = branch_stack[-1]
            condition_active = not branch_taken
            branch_stack[-1] = (parent_active, True)
            active_stack[-1] = parent_active and condition_active
        elif directive == "endif" and branch_stack:
            branch_stack.pop()
            active_stack.pop()

    return "\n".join(output)


def strip_comments(text: str) -> str:
    without_block_comments = re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )
    return re.sub(r"//.*", "", without_block_comments)


def split_top_level_commas(text: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    start = 0
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth = max(0, depth - 1)
        elif character == "," and depth == 0:
            parts.append(text[start:index])
            start = index + 1
    parts.append(text[start:])
    return parts


def remove_leading_annotation(text: str) -> str:
    current = text.strip()
    while current.startswith("_"):
        macro_match = re.match(r"(__?[A-Za-z]\w*)", current)
        if macro_match is None:
            break

        index = macro_match.end()
        while index < len(current) and current[index].isspace():
            index += 1

        if index < len(current) and current[index] == "(":
            depth = 1
            index += 1
            while index < len(current) and depth > 0:
                if current[index] == "(":
                    depth += 1
                elif current[index] == ")":
                    depth -= 1
                index += 1

        current = current[index:].strip()

    return current


def normalize_type_spelling(type_spelling: str) -> str:
    normalized = " ".join(type_spelling.replace("\t", " ").split())
    normalized = normalized.replace(" *", "*")
    normalized = normalized.replace("* ", "*")
    normalized = normalized.replace(" &", "&")
    normalized = normalized.replace("& ", "&")
    return normalized


def parse_parameter(raw_parameter: str, index: int) -> tuple[str, str] | None:
    parameter = remove_leading_annotation(" ".join(raw_parameter.split()))
    if parameter in {"", "VOID", "void"}:
        return None

    parameter = parameter.rstrip(",")
    name_match = re.search(r"([A-Za-z_]\w*)(?:\s*\[[^\]]*\])?\s*$", parameter)
    if name_match is None:
        return (f"Argument{index}", normalize_type_spelling(parameter))

    name = name_match.group(1)
    type_spelling = parameter[: name_match.start()].strip()
    if type_spelling == "":
        return (f"Argument{index}", normalize_type_spelling(parameter))

    return (name, normalize_type_spelling(type_spelling))


def load_phnt_text(phnt_root: Path) -> str:
    chunks: list[str] = []
    for header_name in PHNT_HEADER_NAMES:
        header_path = phnt_root / header_name
        if header_path.exists():
            chunks.append(filter_active_lines(header_path.read_text(encoding="utf-8", errors="ignore")))
    return strip_comments("\n".join(chunks))


def extract_prototypes(phnt_root: Path) -> dict[str, Prototype]:
    text = load_phnt_text(phnt_root)
    pattern = re.compile(
        r"\b(?:NTSYSCALLAPI|NTSYSAPI)\b\s+"
        r"(?P<return_type>.*?)"
        r"\bNTAPI\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*"
        r"\((?P<arguments>.*?)\)\s*;",
        re.DOTALL,
    )

    prototypes: dict[str, Prototype] = {}
    for match in pattern.finditer(text):
        name = match.group("name")
        if not name.startswith("Nt") or name.startswith("NtWow64"):
            continue

        argument_names: list[str] = []
        argument_type_names: list[str] = []
        for argument_index, raw_argument in enumerate(split_top_level_commas(match.group("arguments")), start=1):
            parsed_parameter = parse_parameter(raw_argument, argument_index)
            if parsed_parameter is None:
                continue

            argument_name, argument_type_name = parsed_parameter
            argument_names.append(argument_name)
            argument_type_names.append(argument_type_name)

        prototypes.setdefault(
            name,
            Prototype(
                name=name,
                argument_names=tuple(argument_names),
                argument_type_names=tuple(argument_type_names),
            ),
        )

    return prototypes


def find_dumpbin() -> Path | None:
    from_path = shutil_which("dumpbin.exe")
    if from_path is not None:
        return Path(from_path)

    candidates = glob.glob(
        r"C:\Program Files\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe"
    )
    candidates.extend(
        glob.glob(
            r"C:\Program Files (x86)\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe"
        )
    )
    if not candidates:
        return None

    return Path(sorted(candidates, reverse=True)[0])


def shutil_which(name: str) -> str | None:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.exists():
            return str(candidate)
    return None


def read_exports_with_dumpbin(dumpbin: Path, image_path: Path) -> set[str]:
    completed = subprocess.run(
        [str(dumpbin), "/exports", str(image_path)],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    exports: set[str] = set()
    for line in completed.stdout.splitlines():
        match = re.match(r"\s*\d+\s+[0-9A-Fa-f]+\s+[0-9A-Fa-f]+\s+(\S+)", line)
        if match is not None:
            exports.add(match.group(1).split("=")[0])
    return exports


def rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int:
    for virtual_address, virtual_size, raw_pointer, raw_size in sections:
        size = max(virtual_size, raw_size)
        if virtual_address <= rva < virtual_address + size:
            return raw_pointer + (rva - virtual_address)
    raise ValueError(f"RVA 0x{rva:X} is outside all PE sections")


def read_c_string(data: bytes, offset: int) -> str:
    end = data.index(0, offset)
    return data[offset:end].decode("ascii", errors="replace")


def read_exports_with_pe_parser(image_path: Path) -> set[str]:
    data = image_path.read_bytes()
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ValueError(f"{image_path} is not a PE image")

    coff_offset = pe_offset + 4
    number_of_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    optional_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    optional_header_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, optional_header_offset)[0]
    data_directory_offset = optional_header_offset + (112 if magic == 0x20B else 96)
    export_rva, export_size = struct.unpack_from("<II", data, data_directory_offset)
    if export_rva == 0 or export_size == 0:
        return set()

    section_offset = optional_header_offset + optional_header_size
    sections: list[tuple[int, int, int, int]] = []
    for index in range(number_of_sections):
        current_offset = section_offset + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, current_offset + 8)
        sections.append((virtual_address, virtual_size, raw_pointer, raw_size))

    export_offset = rva_to_offset(export_rva, sections)
    (
        _characteristics,
        _time_date_stamp,
        _major_version,
        _minor_version,
        _name,
        _base,
        _number_of_functions,
        number_of_names,
        _address_of_functions,
        address_of_names,
        _address_of_name_ordinals,
    ) = struct.unpack_from("<IIHHIIIIIII", data, export_offset)

    names_offset = rva_to_offset(address_of_names, sections)
    exports: set[str] = set()
    for index in range(number_of_names):
        name_rva = struct.unpack_from("<I", data, names_offset + index * 4)[0]
        exports.add(read_c_string(data, rva_to_offset(name_rva, sections)))
    return exports


def collect_export_names(system_root: Path) -> set[str]:
    dll_paths = [system_root / "System32" / "ntdll.dll", system_root / "System32" / "win32u.dll"]
    dumpbin = find_dumpbin()
    exports: set[str] = set()
    for dll_path in dll_paths:
        if dumpbin is not None:
            exports.update(read_exports_with_dumpbin(dumpbin, dll_path))
        else:
            exports.update(read_exports_with_pe_parser(dll_path))
    return exports


def build_signature_entries(prototypes: dict[str, Prototype], export_names: set[str]) -> list[SignatureEntry]:
    entries: list[SignatureEntry] = []
    for export_name in sorted(export_names):
        if export_name.startswith("NtWow64"):
            continue

        prototype = prototypes.get(export_name)
        type_source_name = export_name
        if prototype is None and export_name.startswith("Zw"):
            nt_name = "Nt" + export_name[2:]
            prototype = prototypes.get(nt_name)
            type_source_name = nt_name

        if prototype is None:
            continue

        entries.append(
            SignatureEntry(
                export_name=export_name,
                type_source_name=type_source_name,
                argument_names=prototype.argument_names,
                argument_type_names=prototype.argument_type_names,
            )
        )

    return entries


def cpp_string_literal(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def emit_array(values: tuple[str, ...], indentation: str) -> str:
    if not values:
        return "{}"

    lines = ["{"]
    for value in values:
        lines.append(f"{indentation}{cpp_string_literal(value)},")
    lines.append(indentation[:-4] + "}")
    return "\n".join(lines)


def emit_header() -> str:
    return """// Generated by tools/generate_syscall_signatures.py; do not edit manually.
#pragma once

#include "DirectSyscallDetector/SignaturePrinter.h"

#include <cstddef>
#include <memory>
#include <string_view>

namespace DirectSyscallDetector
{
    [[nodiscard]] std::unique_ptr<const ISyscallSignature> FindGeneratedSyscallSignature(std::string_view functionName);
    [[nodiscard]] std::size_t GeneratedSyscallSignatureCount() noexcept;
}
"""


def emit_cpp(entries: list[SignatureEntry]) -> str:
    lines: list[str] = [
        "// Generated by tools/generate_syscall_signatures.py; do not edit manually.",
        '#include "DirectSyscallDetector/GeneratedSyscallSignatures.h"',
        "",
        '#include "DirectSyscallDetector/NativeApi.h"',
        "",
        "#include <algorithm>",
        "#include <array>",
        "#include <memory>",
        "#include <string_view>",
        "#include <type_traits>",
        "",
        "namespace DirectSyscallDetector",
        "{",
        "    namespace",
        "    {",
        "        struct SignatureRegistration",
        "        {",
        "            std::string_view Name{};",
        "            std::unique_ptr<const ISyscallSignature>(*Factory)() {};",
        "        };",
        "",
        "        using SignatureRegistrationArray = std::array<SignatureRegistration,",
        f"            {len(entries)}>;",
        "",
        "        [[nodiscard]] const SignatureRegistrationArray& SignatureRegistrations() noexcept",
        "        {",
        "            static constexpr SignatureRegistrationArray Registrations{",
    ]

    for entry in entries:
        argument_count = len(entry.argument_names)
        argument_names = emit_array(entry.argument_names, "                        ")
        argument_type_names = emit_array(entry.argument_type_names, "                        ")
        lines.extend(
            [
                "                SignatureRegistration{",
                f"                    {cpp_string_literal(entry.export_name)},",
                "                    []() -> std::unique_ptr<const ISyscallSignature>",
                "                    {",
                f"                        using TFunction = std::remove_pointer_t<decltype(&::{entry.type_source_name})>;",
                "                        return MakeSyscallSignature<TFunction>(",
                f"                            {cpp_string_literal(entry.export_name)},",
                f"                            std::array<std::string_view, {argument_count}>{argument_names},",
                f"                            std::array<std::string_view, {argument_count}>{argument_type_names});",
                "                    }",
                "                },",
            ]
        )

    lines.extend(
        [
            "            };",
            "            return Registrations;",
            "        }",
            "    }",
            "",
            "    std::unique_ptr<const ISyscallSignature> FindGeneratedSyscallSignature(const std::string_view functionName)",
            "    {",
            "        const auto& registrations{ SignatureRegistrations() };",
            "        const auto found{ std::lower_bound(",
            "            registrations.begin(),",
            "            registrations.end(),",
            "            functionName,",
            "            [](const SignatureRegistration& registration, const std::string_view value)",
            "            {",
            "                return registration.Name < value;",
            "            }) };",
            "",
            "        if (registrations.end() == found || found->Name != functionName)",
            "        {",
            "            return nullptr;",
            "        }",
            "",
            "        return found->Factory();",
            "    }",
            "",
            "    std::size_t GeneratedSyscallSignatureCount() noexcept",
            "    {",
            "        return SignatureRegistrations().size();",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def write_if_changed(path: Path, content: str) -> None:
    if path.exists() and path.read_text(encoding="utf-8") == content:
        return
    path.write_text(content, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate PHNT-backed syscall signature registry files.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--system-root", type=Path, default=Path(os.environ.get("SystemRoot", r"C:\Windows")))
    args = parser.parse_args()

    root = args.root.resolve()
    prototypes = extract_prototypes(root / "third_party" / "phnt")
    export_names = collect_export_names(args.system_root)
    entries = build_signature_entries(prototypes, export_names)

    include_path = root / "DirectSyscallDetectorLib" / "include" / "DirectSyscallDetector" / "GeneratedSyscallSignatures.h"
    source_path = root / "DirectSyscallDetectorLib" / "src" / "GeneratedSyscallSignatures.cpp"
    write_if_changed(include_path, emit_header())
    write_if_changed(source_path, emit_cpp(entries))

    print(f"generated {len(entries)} syscall signatures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
