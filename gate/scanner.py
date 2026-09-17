"""A deliberately small, standard-library-only static scanner.

The scanner reads regular files below one chosen directory. It does not invoke
Git, a package manager, a shell, a network client, an archive extractor, or an
interpreter for inspected content. Its output is a limited receipt, not an
execution approval or a claim that the inspected source is safe.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any


class GateError(ValueError):
    """Raised when the scanner cannot safely establish its local input scope."""


CONTRACT = "agent-safe-github-lab-static-receipt-v1"
DEFAULT_MAX_FILES = 500
DEFAULT_MAX_DIRECTORIES = 500
DEFAULT_MAX_FILE_BYTES = 512 * 1024
INSTRUCTION_FILENAMES = {
    "AGENTS.md",
    "CLAUDE.md",
    "GEMINI.md",
    "INSTALL.md",
    "README.md",
    "SKILL.md",
}
ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".xz", ".zip"}
BIDI_MARKERS = {"\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"}

PROMPT_INJECTION = re.compile(
    r"(?:ignore|disregard|override).{0,80}(?:previous|all).{0,80}(?:rule|instruction|safety)"
    r"|(?:reveal|exfiltrate).{0,80}(?:environment|secret|token|credential)"
    r"|(?:игнорируй|не\s+учитывай).{0,80}(?:предыдущ|все).{0,80}(?:правил|инструкц|ограничен)"
    r"|(?:раскрой|передай).{0,80}(?:переменн.{0,20}окруж|секрет|токен|учётн)",
    re.IGNORECASE,
)
NETWORK_EGRESS = re.compile(
    r"https?://|\b(?:fetch|curl|wget|requests\.(?:get|post)|urllib\.|http\.request)\b",
    re.IGNORECASE,
)
SECRET_ACCESS = re.compile(
    r"(?:process\.env\.|os\.environ|os\.getenv\(|getenv\(|\$\{?[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|KEY|PASSWORD)[A-Z0-9_]*\}?)",
    re.IGNORECASE,
)
SECOND_STAGE = re.compile(
    r"\b(?:curl|wget)\b[^\n|]{0,400}\|\s*(?:ba)?sh\b|"
    r"\b(?:curl|wget)\b[^\n|]{0,400}\|\s*(?:python(?:3)?|node)\b|"
    r"\b(?:download|bootstrap|self[- ]?update)\b.{0,120}\b(?:execute|install|run)\b",
    re.IGNORECASE,
)
MUTABLE_REFERENCE = re.compile(r"(?:@|#)(?:main|master|dev|latest|next)\b", re.IGNORECASE)
OBFUSCATED_CODE = re.compile(
    r"(?:base64\.(?:b64decode|decode)|fromcharcode\(|(?:powershell|pwsh).{0,40}(?:-enc|-encodedcommand))",
    re.IGNORECASE,
)
def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _relative(root: Path, candidate: Path) -> str:
    return candidate.relative_to(root).as_posix()


def _finding(
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, int | None]],
    *,
    category: str,
    severity: str,
    path: str,
    line: int | None,
    detail: str,
    excerpt: str | None = None,
) -> None:
    # A receipt intentionally contains no source excerpts: untrusted input can
    # hold secrets, credentials, personal data, or more hostile instructions.
    del excerpt
    key = (category, path, line)
    if key in seen:
        return
    seen.add(key)
    item: dict[str, Any] = {
        "category": category,
        "severity": severity,
        "path": path,
        "line": line,
        "detail": detail,
    }
    findings.append(item)


def _scan_text(
    text: str,
    relative_path: str,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, int | None]],
) -> None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        if any(marker in line for marker in BIDI_MARKERS):
            _finding(
                findings,
                seen,
                category="bidi_control_character",
                severity="high",
                path=relative_path,
                line=line_number,
                detail="Bidirectional control characters can conceal the apparent order of text.",
                excerpt=line,
            )
        if PROMPT_INJECTION.search(line):
            _finding(
                findings,
                seen,
                category="prompt_injection",
                severity="high",
                path=relative_path,
                line=line_number,
                detail="Untrusted text attempts to alter instructions or request sensitive data.",
                excerpt=line,
            )
        has_network = bool(NETWORK_EGRESS.search(line))
        has_secret_access = bool(SECRET_ACCESS.search(line))
        if has_network:
            _finding(
                findings,
                seen,
                category="network_egress",
                severity="medium",
                path=relative_path,
                line=line_number,
                detail="Static text contains a network source or sink; no request was made.",
                excerpt=line,
            )
        if has_secret_access:
            _finding(
                findings,
                seen,
                category="secret_access",
                severity="medium",
                path=relative_path,
                line=line_number,
                detail="Static text accesses an environment-derived secret-shaped value.",
                excerpt=line,
            )
        if has_network and has_secret_access:
            _finding(
                findings,
                seen,
                category="possible_secret_to_network",
                severity="high",
                path=relative_path,
                line=line_number,
                detail="Network activity and secret access occur together in one static statement.",
                excerpt=line,
            )
        if SECOND_STAGE.search(line):
            _finding(
                findings,
                seen,
                category="second_stage_download",
                severity="high",
                path=relative_path,
                line=line_number,
                detail="A downloaded second stage appears to be sent directly to an interpreter or installer.",
                excerpt=line,
            )
        if OBFUSCATED_CODE.search(line):
            _finding(
                findings,
                seen,
                category="obfuscated_code",
                severity="high",
                path=relative_path,
                line=line_number,
                detail="Encoded or dynamically assembled code needs a separate, human-readable review.",
                excerpt=line,
            )
        if MUTABLE_REFERENCE.search(line) and ("git+" in line.lower() or "uses:" in line.lower()):
            _finding(
                findings,
                seen,
                category="mutable_reference",
                severity="medium",
                path=relative_path,
                line=line_number,
                detail="A branch, tag, or moving label is used where an immutable digest is safer.",
                excerpt=line,
            )


def _scan_package_manifest(
    text: str,
    relative_path: str,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, int | None]],
) -> None:
    if not Path(relative_path).name.startswith("package.json"):
        return
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError:
        _finding(
            findings,
            seen,
            category="invalid_package_manifest",
            severity="medium",
            path=relative_path,
            line=None,
            detail="The package manifest is not valid JSON, so its scripts could not be reliably reviewed.",
        )
        return
    if not isinstance(manifest, dict):
        _finding(
            findings,
            seen,
            category="invalid_package_manifest",
            severity="medium",
            path=relative_path,
            line=None,
            detail="The package manifest is valid JSON but is not a JSON object.",
        )
        return
    scripts = manifest.get("scripts", {})
    if not isinstance(scripts, dict):
        return
    lifecycle = {"preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare"}
    for name, command in scripts.items():
        if name in lifecycle:
            _finding(
                findings,
                seen,
                category="npm_lifecycle_script",
                severity="high",
                path=relative_path,
                line=None,
                detail=f"The {name} lifecycle hook can execute during package installation.",
                excerpt=f"{name}: {command}",
            )


def _scan_workflow(
    text: str,
    relative_path: str,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, int | None]],
) -> None:
    if "/.github/workflows/" not in f"/{relative_path}":
        return
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if re.match(r"(?:on:\s*)?(?:pull_request_target|workflow_run)\b", stripped):
            _finding(
                findings,
                seen,
                category="actions_privileged_event",
                severity="high",
                path=relative_path,
                line=line_number,
                detail="The workflow uses an event that needs a separate trust-boundary review.",
                excerpt=line,
            )
        if re.match(r"permissions:\s*(?:write-all|\{.*write.*\})", stripped, re.IGNORECASE):
            _finding(
                findings,
                seen,
                category="actions_broad_permissions",
                severity="high",
                path=relative_path,
                line=line_number,
                detail="The workflow requests broad write permissions instead of job-specific minimum access.",
                excerpt=line,
            )
        if re.match(r"runs-on:\s*(?:\[?\s*)?self-hosted\b", stripped, re.IGNORECASE):
            _finding(
                findings,
                seen,
                category="actions_self_hosted_runner",
                severity="high",
                path=relative_path,
                line=line_number,
                detail="Untrusted workflow code on a self-hosted runner needs a separate host and credential boundary review.",
                excerpt=line,
            )
        uses_match = re.search(r"\buses:\s*[^@\s]+@([^\s#]+)", stripped)
        if uses_match and not re.fullmatch(r"[0-9a-fA-F]{40}", uses_match.group(1)):
            _finding(
                findings,
                seen,
                category="actions_unpinned_reference",
                severity="medium",
                path=relative_path,
                line=line_number,
                detail="A third-party Action is not pinned to a full immutable commit SHA.",
                excerpt=line,
            )


def _scan_source_metadata(
    text: str,
    relative_path: str,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str, int | None]],
) -> None:
    if Path(relative_path).name.startswith(".gitmodules"):
        _finding(
            findings,
            seen,
            category="git_submodule",
            severity="high",
            path=relative_path,
            line=None,
            detail="Git submodules introduce additional repositories that require their own admission receipts.",
        )
    lfs_match = re.search(r"(?m)^version https://[^\s]*/git-lfs", text)
    if lfs_match:
        _finding(
            findings,
            seen,
            category="git_lfs_pointer",
            severity="high",
            path=relative_path,
            line=text[: lfs_match.start()].count("\n") + 1,
            detail="A Git LFS pointer represents content fetched outside the ordinary source tree.",
            excerpt=text.splitlines()[0],
        )
    if Path(relative_path).name.startswith("pyproject.toml") and "[build-system]" in text:
        _finding(
            findings,
            seen,
            category="python_build_backend",
            severity="high",
            path=relative_path,
            line=None,
            detail="Python build-system configuration can select code that runs during package build or installation.",
        )


def _verdict(findings: list[dict[str, Any]]) -> str:
    if any(item["severity"] == "high" for item in findings):
        return "STOP"
    if findings:
        return "REVIEW_REQUIRED"
    return "STATIC_REVIEW_COMPLETE"


def _read_regular_file(candidate: Path, max_file_bytes: int) -> tuple[bytes | None, int | None, str | None]:
    """Read one bounded regular file without following a final symlink race."""
    try:
        initial_metadata = candidate.lstat()
    except OSError as error:
        return None, None, f"lstat:{type(error).__name__}"
    if not stat.S_ISREG(initial_metadata.st_mode):
        return None, None, "non_regular"
    if initial_metadata.st_size > max_file_bytes:
        return None, None, "oversize"
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        file_descriptor = os.open(candidate, flags)
    except OSError as error:
        return None, None, f"open:{type(error).__name__}"
    try:
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None, None, "non_regular"
        if metadata.st_size > max_file_bytes:
            return None, None, "oversize"
        with os.fdopen(file_descriptor, "rb", closefd=False) as opened_file:
            payload = opened_file.read(max_file_bytes + 1)
        if len(payload) > max_file_bytes:
            return None, None, "oversize"
        return payload, metadata.st_mode, None
    finally:
        os.close(file_descriptor)


def scan_directory(
    path: str | Path,
    *,
    max_files: int = DEFAULT_MAX_FILES,
    max_directories: int = DEFAULT_MAX_DIRECTORIES,
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
) -> dict[str, Any]:
    """Return a deterministic receipt for a bounded static local directory scan."""
    root = Path(path).expanduser()
    if root.is_symlink() or not root.exists() or not root.is_dir():
        raise GateError("input must be an existing directory that is not a symlink")
    if max_files < 1 or max_directories < 1 or max_file_bytes < 1:
        raise GateError("scan limits must be positive")

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int | None]] = set()
    instruction_files: list[str] = []
    digests: list[tuple[str, str]] = []
    files_scanned = 0
    directories_scanned = 0

    def walk_error(error: OSError) -> None:
        try:
            relative_path = _relative(root, Path(error.filename or "."))
        except ValueError:
            relative_path = "."
        _finding(
            findings,
            seen,
            category="incomplete_static_review",
            severity="high",
            path=relative_path,
            line=None,
            detail="A directory could not be enumerated, so the static review is incomplete.",
        )

    for current, directory_names, file_names in os.walk(root, followlinks=False, onerror=walk_error):
        directories_scanned += 1
        if directories_scanned > max_directories:
            _finding(
                findings,
                seen,
                category="incomplete_static_review",
                severity="high",
                path=".",
                line=None,
                detail=f"The scan reached the {max_directories}-directory limit before the tree was fully read.",
            )
            break
        current_path = Path(current)
        retained_directories: list[str] = []
        for directory_name in sorted(directory_names):
            candidate = current_path / directory_name
            relative_path = _relative(root, candidate)
            if directory_name == ".git":
                continue
            if candidate.is_symlink():
                _finding(
                    findings,
                    seen,
                    category="symlink",
                    severity="high",
                    path=relative_path,
                    line=None,
                    detail="Symlinked directories are excluded so the scan cannot escape its declared scope.",
                )
                continue
            retained_directories.append(directory_name)
        directory_names[:] = retained_directories

        for file_name in sorted(file_names):
            candidate = current_path / file_name
            relative_path = _relative(root, candidate)
            if candidate.is_symlink():
                _finding(
                    findings,
                    seen,
                    category="symlink",
                    severity="high",
                    path=relative_path,
                    line=None,
                    detail="Symlinked files are excluded so the scan cannot escape its declared scope.",
                )
                continue
            if files_scanned >= max_files:
                _finding(
                    findings,
                    seen,
                    category="incomplete_static_review",
                    severity="high",
                    path=".",
                    line=None,
                    detail=f"The scan reached the {max_files}-file limit before the tree was fully read.",
                )
                break
            files_scanned += 1
            if file_name in INSTRUCTION_FILENAMES:
                instruction_files.append(relative_path)
            if candidate.suffix.lower() in ARCHIVE_SUFFIXES:
                _finding(
                    findings,
                    seen,
                    category="archive",
                    severity="high",
                    path=relative_path,
                    line=None,
                    detail="Archives require a separately bounded inspection; this scanner never extracts them.",
                )
                continue
            payload, mode, read_problem = _read_regular_file(candidate, max_file_bytes)
            if read_problem == "non_regular":
                _finding(
                    findings,
                    seen,
                    category="non_regular_file",
                    severity="high",
                    path=relative_path,
                    line=None,
                    detail="Only regular files are read; FIFOs, devices, and sockets stay untouched.",
                )
                continue
            if read_problem == "oversize":
                _finding(
                    findings,
                    seen,
                    category="incomplete_static_review",
                    severity="high",
                    path=relative_path,
                    line=None,
                    detail=f"The file exceeds the {max_file_bytes}-byte static-read limit.",
                )
                continue
            if read_problem:
                _finding(
                    findings,
                    seen,
                    category="unreadable_file",
                    severity="high",
                    path=relative_path,
                    line=None,
                    detail="The file could not be opened as a bounded regular file.",
                )
                continue
            assert payload is not None
            digests.append((relative_path, _sha256(payload)))
            if mode is not None and mode & 0o111:
                _finding(
                    findings,
                    seen,
                    category="executable_file",
                    severity="high",
                    path=relative_path,
                    line=None,
                    detail="Executable files need separate admission and are not run by this scanner.",
                )
            if b"\x00" in payload:
                _finding(
                    findings,
                    seen,
                    category="binary_or_nontext",
                    severity="medium",
                    path=relative_path,
                    line=None,
                    detail="Binary-like content was not interpreted as text.",
                )
                continue
            try:
                text = payload.decode("utf-8")
            except UnicodeDecodeError:
                _finding(
                    findings,
                    seen,
                    category="non_utf8_text",
                    severity="medium",
                    path=relative_path,
                    line=None,
                    detail="Non-UTF-8 content was not interpreted as instruction text.",
                )
                continue
            _scan_text(text, relative_path, findings, seen)
            _scan_package_manifest(text, relative_path, findings, seen)
            _scan_workflow(text, relative_path, findings, seen)
            _scan_source_metadata(text, relative_path, findings, seen)
        else:
            continue
        break

    tree_digest = _sha256(
        "\n".join(f"{relative_path}:{digest}" for relative_path, digest in sorted(digests)).encode("utf-8")
    )
    findings.sort(key=lambda item: (item["path"], item["line"] is None, item["line"] or 0, item["category"]))
    return {
        "contract": CONTRACT,
        "scope": root.name,
        "files_scanned": files_scanned,
        "reviewed_content_sha256": tree_digest,
        "instruction_files": sorted(instruction_files),
        "excluded_paths": [".git/ metadata is not read"],
        "directories_scanned": directories_scanned,
        "findings": findings,
        "verdict": _verdict(findings),
        "limitations": [
            "Static review does not authorize execution.",
            "No network, install, clone, archive extraction, or runtime behavior was tested.",
            "Heuristics can miss risks and can report false positives; human review remains required.",
            "The reviewed-content digest excludes Git metadata, file permissions, and unread or excluded objects.",
            "The scanner is not a safe boundary for a tree that an attacker can modify during scanning.",
            "Relative paths can contain sensitive names; review a receipt before sharing it outside its intended scope.",
            "Directory enumeration is bounded by count, but one very large directory can still consume local resources.",
        ],
    }
