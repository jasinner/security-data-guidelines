"""
``bundled()`` / ``golang()`` from Koji Provides (Deptopia ``internal/sources/rpm.go``).

Lightweight SPDX 2 document fragments for manifests (packages + DEPENDENCY_OF).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

LANG_TO_PURL_TYPE: dict[str, str] = {
    "golang": "golang",
    "python": "pypi",
    "nodejs": "npm",
    "rust": "cargo",
    "ruby": "gem",
    "java": "maven",
    "generic": "generic",
}


@dataclass
class RpmDep:
    """Koji ``getRPMDeps`` row."""

    name: str
    version: str
    dep_type: int  # 0 requires, 1 provides


@dataclass
class BundledDep:
    """Single ``bundled()`` or ``golang()`` provide after parsing."""

    path: str
    version: str
    lang: str  # "generic", "golang", "python", ...


def _bundled_purl(dep: BundledDep) -> str:
    purl_type = LANG_TO_PURL_TYPE.get(dep.lang, "generic")
    ver = f"@{dep.version}" if dep.version else ""
    return f"pkg:{purl_type}/{dep.path}{ver}"


def _dep_lang_from_inner(name_inner: str) -> tuple[str, str]:
    """Map inner provide name → (path, lang). Mirrors ``getDepListLangFromName``."""
    if name_inner.startswith("golang)") and "(" in name_inner:
        ss = name_inner[len("golang)") :].lstrip()
        if ss.startswith("(") and ")" in ss:
            path = ss[1 : ss.index(")")]
            return path, "golang"

    s = name_inner
    if " with " in s:
        s = s.strip().strip("()")
        s = s.split(" ", 1)[0]

    parts = s.split("(", 1)
    if len(parts) > 1:
        prefix, rest = parts[0], parts[1].rstrip(")")
        lp = prefix.lower()
        if "golang" in lp:
            return rest, "golang"
        if "python" in lp:
            return rest, "python"
        if "npm" in lp or "nodejs" in lp:
            return rest, "nodejs"
        if "ruby" in lp:
            return rest, "ruby"
        if "crate" in lp:
            return rest, "rust"
        if "mvn" in lp:
            return rest, "java"

    sl = name_inner.lower()
    if sl.startswith("nodejs-"):
        return name_inner.split("-", 1)[1], "nodejs"
    if sl.startswith("python-") or sl.startswith("python3-") or sl.startswith("python2-"):
        return name_inner.split("-", 1)[1], "python"
    if sl.startswith("rubygem-"):
        return name_inner.split("-", 1)[1], "ruby"

    return name_inner, "generic"


def _parse_wrapped(
    prefix: str, rpm_name: str, rpm_ver: str, default_lang: str
) -> BundledDep | None:
    pfx = prefix + "("
    if not rpm_name.startswith(pfx) or not rpm_name.endswith(")"):
        return None
    inner = rpm_name[len(pfx) : -1]
    path, lang = _dep_lang_from_inner(inner)
    if lang == "generic" and default_lang != "generic":
        lang = default_lang
    return BundledDep(path=path, version=rpm_ver, lang=lang)


def bundled_golang_from_provides(provides: list[RpmDep]) -> list[BundledDep]:
    """Extract ``bundled(...)`` and ``golang(...)`` Provides (type 1 rows)."""
    out: list[BundledDep] = []
    seen: set[tuple[str, str, str]] = set()
    for d in provides:
        b = _parse_wrapped("bundled", d.name, d.version, "generic")
        if b:
            key = (b.path, b.version, b.lang)
            if key not in seen:
                seen.add(key)
                out.append(b)
            continue
        g = _parse_wrapped("golang", d.name, d.version, "golang")
        if g:
            key = (g.path, g.version, g.lang)
            if key not in seen:
                seen.add(key)
                out.append(g)
    return out


def _ref_id(s: str) -> str:
    h = hashlib.sha256(s.encode("utf-8")).hexdigest()[:12]
    return f"SPDXRef-Bundled-{h}"


def bundled_provides_to_spdx_fragments(
    bundled: list[BundledDep],
    *,
    srpm_spdx_id: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Return ``(packages, relationships)`` SPDX JSON-LD-style dicts (subset).

    Each bundled dep becomes a package; ``DEPENDENCY_OF`` links it to ``srpm_spdx_id``.
    """
    packages: list[dict[str, Any]] = []
    rels: list[dict[str, Any]] = []
    for b in bundled:
        pid = _ref_id(f"{b.path}\0{b.version}\0{b.lang}")
        name = f"{b.path} ({b.lang})"
        if b.version:
            name = f"{name} {b.version}"
        packages.append(
            {
                "SPDXID": pid,
                "name": name,
                "versionInfo": b.version or "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "LIBRARY",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": _bundled_purl(b),
                    }
                ],
            }
        )
        rels.append(
            {
                "spdxElementId": pid,
                "relationshipType": "DEPENDENCY_OF",
                "relatedSpdxElement": srpm_spdx_id,
            }
        )
    return packages, rels


def bundled_provides_to_cdx_components(bundled: list[BundledDep]) -> list[dict[str, Any]]:
    """Return CycloneDX components for bundled deps (type ``library``)."""
    components: list[dict[str, Any]] = []
    for b in bundled:
        purl = _bundled_purl(b)
        name = f"{b.path} ({b.lang})"
        if b.version:
            name = f"{name} {b.version}"
        components.append(
            {
                "bom-ref": purl,
                "type": "library",
                "name": name,
                "version": b.version or None,
                "purl": purl,
            }
        )
    return components
