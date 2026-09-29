"""Package repository availability helpers for generator tool mode."""

from __future__ import annotations

import gzip
import io
import json
import lzma
import re
import tarfile
from datetime import datetime, timezone
from functools import lru_cache
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


DEBIAN_RELEASES = {
    "trixie": ("current", True, ""),
    "bookworm": ("current", True, ""),
    "bullseye": ("oldstable_lts", True, ""),
    "buster": ("archived", False, "archive.debian.org or snapshot.debian.org"),
    "stretch": ("archived", False, "archive.debian.org or snapshot.debian.org"),
    "jessie": ("archived", False, "archive.debian.org or snapshot.debian.org"),
}

DEBIAN_RELEASE_ALIASES = {
    "13": "trixie",
    "12": "bookworm",
    "11": "bullseye",
    "10": "buster",
    "9": "stretch",
    "8": "jessie",
}

UBUNTU_RELEASES = {
    "24.04": ("current_lts", True, ""),
    "22.04": ("current_lts", True, ""),
    "20.04": ("esm_lts", True, ""),
    "18.04": ("esm_or_archived", False, "old-releases.ubuntu.com"),
    "21.10": ("archived", False, "old-releases.ubuntu.com"),
    "21.04": ("archived", False, "old-releases.ubuntu.com"),
    "16.04": ("archived", False, "old-releases.ubuntu.com"),
    "noble": ("current_lts", True, ""),
    "jammy": ("current_lts", True, ""),
    "focal": ("esm_lts", True, ""),
    "bionic": ("esm_or_archived", False, "old-releases.ubuntu.com"),
    "impish": ("archived", False, "old-releases.ubuntu.com"),
}

UBUNTU_RELEASE_ALIASES = {
    "24.04": "noble",
    "22.04": "jammy",
    "20.04": "focal",
    "18.04": "bionic",
    "21.10": "impish",
}

ALPINE_RELEASES = {
    "3.22": ("current", True, ""),
    "3.21": ("current", True, ""),
    "3.20": ("current", True, ""),
    "3.19": ("oldstable", True, ""),
    "3.18": ("oldstable", True, ""),
    "3.17": ("archived", False, "dl-cdn.alpinelinux.org/alpine archived branch"),
    "3.16": ("archived", False, "dl-cdn.alpinelinux.org/alpine archived branch"),
}

CENTOS_RELEASES = {
    "9": ("stream_current", True, ""),
    "8": ("archived", False, "vault.centos.org"),
    "7": ("archived", False, "vault.centos.org"),
}

ROCKY_RELEASES = {
    "10": ("current", True, ""),
    "9": ("current", True, ""),
    "8": ("supported", True, ""),
}

ALMA_RELEASES = {
    "10": ("current", True, ""),
    "9": ("current", True, ""),
    "8": ("supported", True, ""),
}


def check_package_version(
    *,
    image_ref: str,
    package_name: str = "",
    version: str = "",
    available_package_names: frozenset[str] | None = None,
) -> dict:
    """Check base image package sources and, when possible, exact package version availability."""
    distribution, release = _parse_image_ref(image_ref)
    normalized_release = _normalize_release(distribution, release)
    status, default_sources_available, replacement_source = _release_status(
        distribution,
        normalized_release,
    )
    notes = []
    if status == "unknown":
        notes.append("Unknown distribution or release; package source status is not verified.")
    elif default_sources_available:
        notes.append("Default package sources are expected to be usable for this release.")
    else:
        notes.append("Default package sources are likely unavailable or archived for this release.")
    if normalized_release != release:
        notes.append(f"Release tag '{release}' maps to '{normalized_release}'.")

    package_name = package_name.strip()
    version = version.strip()
    snapshot_info = None
    package_version_verified = False
    default_package_version_available = False
    archive_package_available = False
    requires_archive_source = False
    requires_snapshot_source = False
    available = default_sources_available

    if package_name and version:
        notes.append("Exact package version check requested.")
        if distribution == "debian":
            snapshot_info = _find_debian_snapshot_package(
                package_name=package_name,
                version=version,
                release=normalized_release,
            )
            if snapshot_info:
                package_version_verified = True
                requires_snapshot_source = True
                available = True
                notes.append("Exact package version found in Debian snapshot.")
            else:
                available = False
                notes.append("Exact package version was not found in Debian snapshot.")
        else:
            notes.append("Exact package version verification is not implemented for this distribution.")
            available = False
    elif package_name:
        notes.append("Package existence check requested.")
        package_names = (
            available_package_names
            if available_package_names is not None
            else _available_package_names(distribution, normalized_release)
        )
        if package_name in package_names:
            default_package_version_available = default_sources_available
            archive_package_available = not default_sources_available and bool(
                _archived_source_config(distribution, normalized_release)
            )
            requires_archive_source = archive_package_available
            available = True
            if archive_package_available:
                notes.append(
                    "Package name found in archived distribution repositories; "
                    "replacement package sources are required."
                )
            else:
                notes.append("Package name found in the base image distribution repositories.")
        else:
            available = False
            notes.append("Package name was not found in the checked repositories.")

    result = {
        "image_ref": image_ref,
        "distribution": distribution,
        "release": release,
        "normalized_release": normalized_release,
        "package_name": package_name,
        "version": version,
        "source_status": status,
        "default_sources_likely_available": default_sources_available,
        "default_package_version_available": default_package_version_available,
        "archive_package_available": archive_package_available,
        "requires_archive_source": requires_archive_source,
        "replacement_source_hint": replacement_source,
        "package_version_verified": package_version_verified,
        "requires_snapshot_source": requires_snapshot_source,
        "install_package_name": package_name,
        "install_version": version,
        "evidence_url": _release_evidence_url(distribution),
        "available": available,
        "notes": notes,
    }
    if snapshot_info:
        result.update(snapshot_info)
    source_config = _archived_source_config(distribution, normalized_release)
    if source_config and (archive_package_available or requires_archive_source):
        result.update(source_config)
    return result


def check_package_dependencies(
    *,
    image_ref: str,
    dependencies: list,
) -> dict:
    """Check whether required install dependencies exist for a base image."""
    if _should_skip_dependency_checks(image_ref):
        return _skipped_dependency_check_result(
            image_ref=image_ref,
            dependencies=dependencies,
        )

    normalized_dependencies = []
    for dependency in dependencies:
        if isinstance(dependency, dict):
            normalized_dependencies.append(
                {
                    "package_name": str(dependency.get("package_name", "")).strip(),
                    "version": str(dependency.get("version", "")).strip(),
                    "required": bool(dependency.get("required", True)),
                    "purpose": str(dependency.get("purpose", "")).strip(),
                }
            )
        else:
            normalized_dependencies.append(
                {
                    "package_name": str(dependency).strip(),
                    "version": "",
                    "required": True,
                    "purpose": "",
                }
            )

    distribution, release = _parse_image_ref(image_ref)
    normalized_release = _normalize_release(distribution, release)
    available_package_names = (
        _available_package_names(distribution, normalized_release)
        if any(
            item["package_name"] and not item["version"]
            for item in normalized_dependencies
        )
        else frozenset()
    )

    checks = []
    missing = []
    for dependency in normalized_dependencies:
        package_name = dependency["package_name"]
        version = dependency["version"]
        required = dependency["required"]
        purpose = dependency["purpose"]
        result = check_package_version(
            image_ref=image_ref,
            package_name=package_name,
            version=version,
            available_package_names=(
                available_package_names if not version else None
            ),
        )
        result["required"] = required
        result["purpose"] = purpose
        checks.append(result)
        if required and not result.get("available"):
            missing.append(package_name)
    result = {
        "image_ref": image_ref,
        "dependencies": checks,
        "missing_required_packages": missing,
        "available": not missing,
    }
    source_config = _archived_source_config(distribution, normalized_release)
    if source_config:
        result.update(source_config)
        result["archive_package_available"] = any(
            bool(check.get("archive_package_available")) for check in checks
        )
        result["requires_archive_source"] = bool(result["archive_package_available"])
    return result


def _archived_source_config(distribution: str, release: str) -> dict:
    """Return exact package-manager source facts for supported archived releases."""
    if distribution != "debian" or release not in {"buster", "stretch", "jessie"}:
        return {}
    return {
        "source_status": "archived",
        "default_sources_likely_available": False,
        "replacement_source_list": [
            f"deb http://archive.debian.org/debian {release} main",
            f"deb http://archive.debian.org/debian-security {release}/updates main",
        ],
        "apt_update_options": [
            "Acquire::Check-Valid-Until=false",
        ],
    }


def _find_debian_snapshot_package(
    *,
    package_name: str,
    version: str,
    release: str,
) -> dict | None:
    binary_candidates = _debian_source_binary_candidates(
        source_package=package_name,
        version=version,
    )
    install_package = _choose_install_package(
        source_package=package_name,
        binary_candidates=binary_candidates,
    )
    package_token = quote(install_package, safe="")
    version_token = quote(version, safe="")
    binfiles_url = (
        "https://snapshot.debian.org/mr/binary/"
        f"{package_token}/{version_token}/binfiles"
    )
    binfiles = _fetch_json(binfiles_url)
    if not isinstance(binfiles, dict):
        return None
    files = binfiles.get("result")
    if not isinstance(files, list):
        return None
    chosen = _choose_debian_binary_file(files)
    if not chosen:
        return None
    file_hash = str(chosen.get("hash", "")).strip()
    if not file_hash:
        return None
    info_url = f"https://snapshot.debian.org/mr/file/{quote(file_hash, safe='')}/info"
    info = _fetch_json(info_url)
    if not isinstance(info, dict):
        return None
    info_results = info.get("result")
    if not isinstance(info_results, list) or not info_results:
        return None
    file_info = info_results[0]
    if not isinstance(file_info, dict):
        return None
    first_seen = str(file_info.get("first_seen", "")).strip()
    archive_name = str(file_info.get("archive_name", "debian") or "debian").strip()
    if not first_seen:
        return None
    timestamp = _select_debian_snapshot_timestamp_for_release(
        archive_name=archive_name,
        release=release,
        package_name=install_package,
        version=version,
        first_seen=first_seen,
        architecture=str(chosen.get("architecture", "")).strip() or "amd64",
    )
    if not timestamp:
        return None
    archive_url = f"http://snapshot.debian.org/archive/{archive_name}/{timestamp}/"
    return {
        "source_package_name": package_name,
        "binary_package_candidates": binary_candidates,
        "install_package_name": install_package,
        "install_package_selected_by": (
            "source_binary_package_score"
            if binary_candidates
            else "requested_package_binary_lookup"
        ),
        "snapshot_first_seen": first_seen,
        "snapshot_timestamp": timestamp,
        "snapshot_archive_url": archive_url,
        "snapshot_index_verified": True,
        "snapshot_index_url": _debian_packages_index_url(
            archive_name=archive_name,
            timestamp=timestamp,
            release=release,
            architecture=str(chosen.get("architecture", "")).strip() or "amd64",
        ),
        "source_transport": "http",
        "source_transport_reason": (
            "Use HTTP for Debian snapshot during apt bootstrap because slim images "
            "may not contain CA certificates before apt update."
        ),
        "snapshot_source_list": (
            f"deb [check-valid-until=no] {archive_url} {release} main"
        ),
        "apt_update_options": [
            "-o",
            "Acquire::Check-Valid-Until=false",
        ],
        "pre_install_packages": [],
        "snapshot_binary_architecture": str(chosen.get("architecture", "")).strip(),
        "snapshot_binary_hash": file_hash,
        "snapshot_file_info_url": info_url,
    }


def _select_debian_snapshot_timestamp_for_release(
    *,
    archive_name: str,
    release: str,
    package_name: str,
    version: str,
    first_seen: str,
    architecture: str,
) -> str:
    for timestamp in _debian_snapshot_timestamp_candidates(first_seen):
        if _debian_snapshot_index_has_package(
            archive_name=archive_name,
            timestamp=timestamp,
            release=release,
            architecture=architecture,
            package_name=package_name,
            version=version,
        ):
            return timestamp
    return ""


def _debian_snapshot_timestamp_candidates(first_seen: str) -> list[str]:
    try:
        start = datetime.strptime(first_seen, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return [first_seen]

    candidates = [first_seen]
    year = start.year
    month = start.month
    for _ in range(24):
        month += 1
        if month > 12:
            month = 1
            year += 1
        candidate = datetime(year, month, 1, tzinfo=timezone.utc)
        if candidate > datetime.now(timezone.utc):
            break
        candidates.append(candidate.strftime("%Y%m%dT000000Z"))
    return list(dict.fromkeys(candidates))


def _debian_snapshot_index_has_package(
    *,
    archive_name: str,
    timestamp: str,
    release: str,
    architecture: str,
    package_name: str,
    version: str,
) -> bool:
    packages = _fetch_debian_packages_index(
        archive_name=archive_name,
        timestamp=timestamp,
        release=release,
        architecture=architecture,
    )
    if not packages and architecture != "amd64":
        packages = _fetch_debian_packages_index(
            archive_name=archive_name,
            timestamp=timestamp,
            release=release,
            architecture="amd64",
        )
    if not packages:
        return False
    return (
        f"Package: {package_name}\n" in packages
        and f"Version: {version}\n" in packages
    )


@lru_cache(maxsize=16)
def _fetch_debian_packages_index(
    *,
    archive_name: str,
    timestamp: str,
    release: str,
    architecture: str,
) -> str:
    url = _debian_packages_index_url(
        archive_name=archive_name,
        timestamp=timestamp,
        release=release,
        architecture=architecture,
    )
    request = Request(url, headers={"User-Agent": "db-env-gc/1.0"})
    try:
        with urlopen(request, timeout=20) as response:
            return lzma.decompress(response.read()).decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, lzma.LZMAError):
        return ""


@lru_cache(maxsize=16)
def _available_package_names(distribution: str, release: str) -> frozenset[str]:
    """Load repository indexes once and return all available package names."""
    package_texts: list[tuple[str, str]] = []
    if distribution == "debian":
        source_config = _archived_source_config(distribution, release)
        base_url = (
            "http://archive.debian.org/debian"
            if source_config
            else "https://deb.debian.org/debian"
        )
        package_texts.append(
            (
                "Package: ",
                _fetch_xz_text(
                    f"{base_url}/dists/{release}/"
                    "main/binary-amd64/Packages.xz"
                ),
            )
        )
    elif distribution == "ubuntu":
        package_texts.extend(
            (
                "Package: ",
                _fetch_gzip_text(
                    f"http://archive.ubuntu.com/ubuntu/dists/{release}/"
                    f"{component}/binary-amd64/Packages.gz"
                ),
            )
            for component in ("main", "universe")
        )
    elif distribution == "alpine":
        package_texts.extend(
            (
                "P:",
                _fetch_apkindex(
                    f"https://dl-cdn.alpinelinux.org/alpine/v{release}/"
                    f"{component}/x86_64/APKINDEX.tar.gz"
                ),
            )
            for component in ("main", "community")
        )
    return frozenset(
        line.removeprefix(prefix).strip()
        for prefix, text in package_texts
        for line in text.splitlines()
        if line.startswith(prefix)
    )


@lru_cache(maxsize=16)
def _fetch_xz_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": "db-env-gc/1.0"})
    try:
        with urlopen(request, timeout=20) as response:
            return lzma.decompress(response.read()).decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, lzma.LZMAError):
        return ""


@lru_cache(maxsize=16)
def _fetch_gzip_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": "db-env-gc/1.0"})
    try:
        with urlopen(request, timeout=20) as response:
            return gzip.decompress(response.read()).decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, gzip.BadGzipFile):
        return ""


@lru_cache(maxsize=16)
def _fetch_apkindex(url: str) -> str:
    request = Request(url, headers={"User-Agent": "db-env-gc/1.0"})
    try:
        with urlopen(request, timeout=20) as response:
            with tarfile.open(fileobj=io.BytesIO(response.read()), mode="r:gz") as archive:
                member = archive.extractfile("APKINDEX")
                return member.read().decode("utf-8", errors="replace") if member else ""
    except (HTTPError, URLError, TimeoutError, KeyError, tarfile.TarError):
        return ""


def _debian_packages_index_url(
    *,
    archive_name: str,
    timestamp: str,
    release: str,
    architecture: str,
) -> str:
    index_arch = architecture if architecture and architecture != "all" else "amd64"
    return (
        f"http://snapshot.debian.org/archive/{archive_name}/{timestamp}/"
        f"dists/{release}/main/binary-{index_arch}/Packages.xz"
    )


def _debian_source_binary_candidates(*, source_package: str, version: str) -> list[str]:
    source_token = quote(source_package, safe="")
    version_token = quote(version, safe="")
    binpackages_url = (
        "https://snapshot.debian.org/mr/package/"
        f"{source_token}/{version_token}/binpackages"
    )
    binpackages = _fetch_json(binpackages_url)
    if not isinstance(binpackages, dict):
        return []
    result = binpackages.get("result")
    if not isinstance(result, list):
        return []
    candidates = {
        str(item.get("name", "")).strip()
        for item in result
        if isinstance(item, dict) and str(item.get("name", "")).strip()
    }
    return sorted(candidates)


def _choose_install_package(
    *,
    source_package: str,
    binary_candidates: list[str],
) -> str:
    if not binary_candidates:
        return source_package
    return max(
        binary_candidates,
        key=lambda name: (_install_package_score(source_package, name), -len(name), name),
    )


def _install_package_score(source_package: str, binary_package: str) -> int:
    source = source_package.strip().lower()
    name = binary_package.strip().lower()
    parts = [part for part in name.replace("_", "-").split("-") if part]
    score = 0
    if name == f"{source}-server":
        score += 120
    if "server" in parts or name.endswith("server"):
        score += 100
    if "daemon" in parts or name.endswith("d"):
        score += 40
    if source and name.startswith(source):
        score += 20
    if name == source:
        score += 50

    negative_terms = {
        "client",
        "common",
        "dbg",
        "dbgsym",
        "dev",
        "doc",
        "examples",
        "lib",
        "plugin",
        "sentinel",
        "test",
        "tools",
    }
    for term in negative_terms:
        if term in parts or name.endswith(f"-{term}") or name.endswith(term):
            score -= 60
    return score


def _choose_debian_binary_file(files: list) -> dict | None:
    candidates = [item for item in files if isinstance(item, dict)]
    for architecture in ("amd64", "all"):
        for item in candidates:
            if str(item.get("architecture", "")).strip() == architecture:
                return item
    return candidates[0] if candidates else None


def _fetch_json(url: str) -> object | None:
    request = Request(url, headers={"User-Agent": "db-env-gc/1.0"})
    try:
        with urlopen(request, timeout=20) as response:
            return json.loads(response.read().decode("utf-8", errors="replace"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError):
        return None


def _parse_image_ref(image_ref: str) -> tuple[str, str]:
    ref = image_ref.strip().split("@", 1)[0]
    image_without_tag, tag = (ref.rsplit(":", 1) + ["latest"])[:2] if ":" in ref.rsplit("/", 1)[-1] else (ref, "latest")
    repository = image_without_tag.rsplit("/", 1)[-1].strip().lower()
    normalized_distribution = _normalize_distribution(repository)
    if _is_native_distribution_image(normalized_distribution):
        return normalized_distribution, tag.strip().lower()
    distribution_override, release_override = _distribution_release_from_tag(tag.strip().lower())
    if distribution_override and release_override:
        return distribution_override, release_override
    return normalized_distribution, tag.strip().lower()


def _distribution_release_from_tag(tag: str) -> tuple[str, str]:
    """Map distro-suffixed image tags to package repository identities."""
    tokens = _tag_tokens(tag)
    for token in tokens:
        if token in UBUNTU_RELEASES:
            return "ubuntu", token
        if token.startswith("ubuntu"):
            suffix = token.removeprefix("ubuntu")
            if suffix in UBUNTU_RELEASES or suffix in UBUNTU_RELEASE_ALIASES:
                return "ubuntu", suffix
    for token in tokens:
        if token in DEBIAN_RELEASES:
            return "debian", token
        if token.startswith("debian"):
            suffix = token.removeprefix("debian")
            if suffix in DEBIAN_RELEASES or suffix in DEBIAN_RELEASE_ALIASES:
                return "debian", suffix
    for token in tokens:
        if token in ALPINE_RELEASES:
            return "alpine", token
        if token.startswith("alpine"):
            suffix = token.removeprefix("alpine").lstrip("-_")
            if suffix in ALPINE_RELEASES:
                return "alpine", suffix
    if "alpine" in tokens:
        for token in tokens:
            if token in ALPINE_RELEASES:
                return "alpine", token
    return "", ""


def _tag_tokens(tag: str) -> list[str]:
    return [token for token in re.split(r"[^a-z0-9.]+", tag.lower()) if token]


def _is_native_distribution_image(distribution: str) -> bool:
    return distribution in {
        "ubuntu",
        "debian",
        "alpine",
        "centos",
        "rocky",
        "alma",
    }


def _should_skip_dependency_checks(image_ref: str) -> bool:
    distribution, _release = _parse_image_ref(image_ref)
    return not _is_native_distribution_image(distribution)


def _skipped_dependency_check_result(*, image_ref: str, dependencies: list) -> dict:
    checks = []
    unchecked = []
    distribution, release = _parse_image_ref(image_ref)
    for dependency in dependencies:
        if isinstance(dependency, dict):
            package_name = str(dependency.get("package_name", "")).strip()
            version = str(dependency.get("version", "")).strip()
            required = bool(dependency.get("required", True))
            purpose = str(dependency.get("purpose", "")).strip()
        else:
            package_name = str(dependency).strip()
            version = ""
            required = True
            purpose = ""
        if package_name:
            unchecked.append(package_name)
        checks.append(
            {
                "image_ref": image_ref,
                "distribution": distribution,
                "release": release,
                "normalized_release": release,
                "package_name": package_name,
                "version": version,
                "source_status": "skipped_unknown_distribution",
                "default_sources_likely_available": False,
                "default_package_version_available": False,
                "replacement_source_hint": "",
                "package_version_verified": False,
                "requires_snapshot_source": False,
                "install_package_name": package_name,
                "install_version": version,
                "evidence_url": "",
                "available": True,
                "verification_skipped": True,
                "required": required,
                "purpose": purpose,
                "notes": [
                    "Dependency repository check skipped because the base image tag does not expose a recognized Linux distribution release token.",
                    "These install dependencies were not repository-verified.",
                ],
            }
        )
    return {
        "image_ref": image_ref,
        "dependencies": checks,
        "missing_required_packages": [],
        "unchecked_required_packages": unchecked,
        "dependency_check_skipped": True,
        "available": True,
        "notes": [
            "Dependency repository check skipped because the base image tag does not expose a recognized Linux distribution release token.",
            "The dependency repository status remains unverified.",
        ],
    }


def _normalize_distribution(repository: str) -> str:
    if repository in {"ubuntu"}:
        return "ubuntu"
    if repository in {"debian"}:
        return "debian"
    if repository in {"alpine"}:
        return "alpine"
    if repository in {"centos"}:
        return "centos"
    if repository in {"rockylinux", "rocky"}:
        return "rocky"
    if repository in {"almalinux", "alma"}:
        return "alma"
    return repository


def _release_status(distribution: str, release: str) -> tuple[str, bool, str]:
    tables = {
        "debian": DEBIAN_RELEASES,
        "ubuntu": UBUNTU_RELEASES,
        "alpine": ALPINE_RELEASES,
        "centos": CENTOS_RELEASES,
        "rocky": ROCKY_RELEASES,
        "alma": ALMA_RELEASES,
    }
    table = tables.get(distribution)
    if not table:
        return "unknown", False, ""
    return table.get(release, ("unknown", False, ""))


def _normalize_release(distribution: str, release: str) -> str:
    base_release = release.split("-", 1)[0].strip().lower()
    if distribution == "debian":
        return DEBIAN_RELEASE_ALIASES.get(base_release, base_release)
    if distribution == "ubuntu":
        return UBUNTU_RELEASE_ALIASES.get(base_release, base_release)
    return base_release


def _release_evidence_url(distribution: str) -> str:
    return {
        "debian": "https://www.debian.org/releases/",
        "ubuntu": "https://wiki.ubuntu.com/Releases",
        "alpine": "https://alpinelinux.org/releases/",
        "centos": "https://www.centos.org/centos-linux-eol/",
        "rocky": "https://rockylinux.org/download",
        "alma": "https://almalinux.org/get-almalinux/",
    }.get(distribution, "")
