#!/usr/bin/env python3
"""
SBOM Compliance Checker

Validates an SBOM (SPDX 2.3 or CycloneDX 1.6) against Red Hat's security-data-guidelines:
  - https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/docs/sbom.md
  - https://github.com/RedHatProductSecurity/security-data-guidelines/blob/main/docs/purl.md

Produces a compliance score from 1 (very poor) to 10 (fully compliant) and lists all
deviations with their severity.

Usage:
    python3 validate_sbom.py <sbom-file>   # .json or .json.gz

Exit codes:
    0 - Score >= 8 (compliant)
    1 - Score 5-7 (partial compliance)
    2 - Score < 5 (non-compliant)
    3 - File could not be parsed
"""

import argparse
import gzip
import json
import re
import sys
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse


# ---------------------------------------------------------------------------
# Finding data model
# ---------------------------------------------------------------------------

CRITICAL = "CRITICAL"
MAJOR = "MAJOR"
MINOR = "MINOR"
INFO = "INFO"

_SEVERITY_ORDER = {CRITICAL: 0, MAJOR: 1, MINOR: 2, INFO: 3}

_SEVERITY_COLORS = {
    CRITICAL: "\033[1;31m",  # bold red
    MAJOR: "\033[33m",  # yellow
    MINOR: "\033[36m",  # cyan
    INFO: "\033[90m",  # dark gray
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "GREEN": "\033[32m",
    "RED": "\033[31m",
}


@dataclass
class Finding:
    severity: str
    category: str
    message: str
    location: str = ""
    count: int = 1  # how many times this finding occurred (for aggregated display)
    sample_locations: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        loc = f" [{self.location}]" if self.location else ""
        return f"[{self.severity}] {self.category}{loc}: {self.message}"


@dataclass
class ValidationResult:
    findings: list[Finding] = field(default_factory=list)
    score: float = 10.0
    format: str = "unknown"
    name: str = ""
    parse_failed: bool = False
    # Maps (severity, category, message) -> Finding index for deduplication
    _dedup: dict = field(default_factory=dict, repr=False)

    def add(self, severity: str, category: str, message: str, location: str = "") -> None:
        key = (severity, category, message)
        if key in self._dedup:
            f = self.findings[self._dedup[key]]
            f.count += 1
            if len(f.sample_locations) < 3 and location and location not in f.sample_locations:
                f.sample_locations.append(location)
        else:
            f = Finding(severity, category, message, location, count=1,
                        sample_locations=[location] if location else [])
            self._dedup[key] = len(self.findings)
            self.findings.append(f)

    def counts(self) -> dict[str, int]:
        """Returns the total count of each severity (including repeated instances)."""
        counts: dict[str, int] = {CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + f.count
        return counts

    def unique_counts(self) -> dict[str, int]:
        """Returns the count of unique finding types per severity."""
        counts: dict[str, int] = {CRITICAL: 0, MAJOR: 0, MINOR: 0, INFO: 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def compute_score(self) -> int:
        """
        Score based on unique finding types (not total occurrences), so that
        a single systemic issue doesn't unfairly dominate the score:
          Score = 10 - (unique_critical * 2.5) - (unique_major * 0.75) - (unique_minor * 0.2)
        But also penalise pervasiveness: if a finding affects > 20% of packages, add extra penalty.
        Floored at 1, rounded to nearest integer.
        """
        uc = self.unique_counts()
        raw = 10.0 - (uc[CRITICAL] * 2.5) - (uc[MAJOR] * 0.75) - (uc[MINOR] * 0.2)
        # Extra penalty if there are any critical/major findings with very high counts
        for f in self.findings:
            if f.severity in (CRITICAL, MAJOR) and f.count > 50:
                raw -= 0.5  # one-time extra for pervasive systemic issues
                break
        return max(1, round(raw))


# ---------------------------------------------------------------------------
# PURL parsing and validation helpers
# ---------------------------------------------------------------------------

_PURL_BASE_RE = re.compile(
    r"^pkg:"
    r"(?P<type>[a-zA-Z][a-zA-Z0-9.+\-]*)/"
    r"(?:(?P<namespace>[^/]+)/)?"
    r"(?P<name>[^@#]+)"
    r"(?:@(?P<version>.+))?$"
)

_EPOCH_IN_VERSION_RE = re.compile(r"^\d+:")


def parse_purl(purl: str) -> dict[str, Any] | None:
    """
    Return a dict of purl components or None if invalid.

    Splits qualifiers and subpath before applying the base regex so that URLs
    embedded inside qualifier values (e.g. download_url=https://...) don't
    confuse the namespace/name/version parsing.
    """
    # Strip scheme prefix
    if not purl.startswith("pkg:"):
        return None

    # Separate subpath
    subpath = ""
    if "#" in purl:
        purl, subpath = purl.rsplit("#", 1)

    # Separate qualifiers
    qualifiers_str = ""
    if "?" in purl:
        purl, qualifiers_str = purl.split("?", 1)

    m = _PURL_BASE_RE.match(purl)
    if not m:
        return None

    result = m.groupdict()
    result["subpath"] = subpath
    result["qualifiers"] = qualifiers_str

    # Parse qualifiers into a dict
    quals: dict[str, str] = {}
    if qualifiers_str:
        for pair in qualifiers_str.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                quals[k.strip()] = v.strip()
    result["qualifiers_dict"] = quals
    return result


def validate_purl(purl: str, result: ValidationResult, location: str) -> dict[str, Any] | None:
    """
    Validate a purl string against Red Hat guidelines.
    Returns parsed purl dict or None if fundamentally invalid.

    Finding messages are written as generic descriptions so that identical issues
    across many packages get deduplicated — the purl/location provides the example.
    """
    parsed = parse_purl(purl)
    if not parsed:
        result.add(CRITICAL, "PURL", "Cannot parse purl (invalid format)", f"{location} — {purl!r}")
        return None

    purl_type = parsed["type"].lower()
    qualifiers = parsed["qualifiers_dict"]

    # ---- RPM ----
    if purl_type == "rpm":
        namespace = (parsed.get("namespace") or "").lower()

        if namespace not in ("redhat", "fedora"):
            result.add(
                MAJOR,
                "PURL/RPM",
                f"RPM purl namespace should be 'redhat' (or 'fedora' for Fedora packages), got {namespace!r}",
                location,
            )
        elif namespace == "fedora":
            result.add(
                MAJOR,
                "PURL/RPM",
                "RPM purl uses 'fedora' namespace — expected 'redhat' for Red Hat-distributed packages",
                location,
            )

        version = parsed.get("version") or ""
        if _EPOCH_IN_VERSION_RE.match(version):
            result.add(
                MAJOR,
                "PURL/RPM",
                "Epoch must use the 'epoch' qualifier, not be embedded in the version string "
                "(e.g. use '?epoch=1' instead of '@1:version')",
                location,
            )

        if "arch" not in qualifiers:
            result.add(
                MAJOR,
                "PURL/RPM",
                "RPM purl is missing the required 'arch' qualifier",
                location,
            )

        if "repository_url" in qualifiers:
            result.add(
                MINOR,
                "PURL/RPM",
                "RPM purl uses 'repository_url' — Red Hat guidelines recommend 'repository_id' instead",
                location,
            )

        if "distro" in qualifiers:
            result.add(
                MINOR,
                "PURL/RPM",
                "RPM purl uses 'distro' qualifier — Red Hat guidelines recommend omitting it",
                location,
            )

    # ---- OCI ----
    elif purl_type == "oci":
        if parsed.get("namespace"):
            result.add(
                MINOR,
                "PURL/OCI",
                "OCI purl should not have a namespace component",
                location,
            )

        if "repository_url" not in qualifiers:
            result.add(
                MINOR,
                "PURL/OCI",
                "OCI purl is missing 'repository_url' qualifier — required for release SBOMs to "
                "identify the container registry (may be absent in build-time SBOMs)",
                location,
            )

        if "tag" not in qualifiers:
            result.add(
                MINOR,
                "PURL/OCI",
                "OCI purl is missing 'tag' qualifier (recommended for unique identification)",
                location,
            )

        version = parsed.get("version") or ""
        if not version or not version.startswith("sha256"):
            result.add(
                MAJOR,
                "PURL/OCI",
                "OCI purl version should be a SHA256 digest (e.g. sha256%3Aabc...)",
                location,
            )
        elif "%" not in version and ":" in version:
            result.add(
                MINOR,
                "PURL/OCI",
                "OCI purl digest colon should be percent-encoded as %3A",
                location,
            )

    # ---- Maven ----
    elif purl_type == "maven":
        if "repository_url" not in qualifiers:
            result.add(
                MINOR,
                "PURL/Maven",
                "Maven purl is missing 'repository_url' qualifier — should point to "
                "https://maven.repository.redhat.com/ga/",
                location,
            )
        elif "maven.repository.redhat.com" not in qualifiers.get("repository_url", ""):
            result.add(
                MINOR,
                "PURL/Maven",
                "Maven purl 'repository_url' should point to the Red Hat Maven repo "
                "(maven.repository.redhat.com)",
                location,
            )

    # ---- Generic ----
    elif purl_type == "generic":
        if "download_url" not in qualifiers:
            result.add(
                MAJOR,
                "PURL/Generic",
                "Generic purl must include a 'download_url' qualifier with the exact artifact URL",
                location,
            )

    return parsed


# ---------------------------------------------------------------------------
# SPDX 2.3 validation
# ---------------------------------------------------------------------------

_UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_RH_NAMESPACES = (
    "https://www.redhat.com/",
    "https://security.access.redhat.com/data/sbom/",
)


def _pkg_location(pkg: dict) -> str:
    spdxid = pkg.get("SPDXID", "?")
    name = pkg.get("name", "?")
    version = pkg.get("versionInfo", "")
    return f"{spdxid} ({name}{'@' + version if version else ''})"


def validate_spdx(data: dict, result: ValidationResult) -> None:
    result.format = "SPDX"

    # ---- Document-level mandatory fields ----
    if data.get("spdxVersion") != "SPDX-2.3":
        result.add(
            CRITICAL,
            "Document",
            f"spdxVersion must be 'SPDX-2.3', got {data.get('spdxVersion')!r}",
        )

    if data.get("dataLicense") != "CC0-1.0":
        result.add(
            CRITICAL,
            "Document",
            f"dataLicense must be 'CC0-1.0', got {data.get('dataLicense')!r}",
        )

    if data.get("SPDXID") != "SPDXRef-DOCUMENT":
        result.add(
            CRITICAL,
            "Document",
            f"SPDXID must be 'SPDXRef-DOCUMENT', got {data.get('SPDXID')!r}",
        )

    name = data.get("name", "")
    result.name = name
    if not name:
        result.add(MAJOR, "Document", "Document 'name' field is missing or empty")

    ns = data.get("documentNamespace", "")
    if not ns:
        result.add(CRITICAL, "Document", "documentNamespace is missing")
    else:
        try:
            parsed_ns = urlparse(ns)
            if not parsed_ns.scheme or not parsed_ns.netloc:
                result.add(CRITICAL, "Document", f"documentNamespace is not a valid URI: {ns!r}")
            elif not any(ns.startswith(rh) for rh in _RH_NAMESPACES):
                result.add(
                    MAJOR,
                    "Document",
                    f"documentNamespace does not use a known Red Hat namespace "
                    f"(expected one starting with {_RH_NAMESPACES}): {ns!r}",
                )
        except Exception:
            result.add(CRITICAL, "Document", f"documentNamespace is not parseable: {ns!r}")

    # ---- creationInfo ----
    ci = data.get("creationInfo")
    if not ci:
        result.add(CRITICAL, "Document/creationInfo", "creationInfo block is missing")
    else:
        created = ci.get("created", "")
        if not created:
            result.add(CRITICAL, "Document/creationInfo", "creationInfo.created is missing")
        elif not _UTC_TIMESTAMP_RE.match(created):
            result.add(
                MAJOR,
                "Document/creationInfo",
                f"creationInfo.created must be in YYYY-MM-DDThh:mm:ssZ (UTC) format, got {created!r}",
            )

        creators: list[str] = ci.get("creators", [])
        if not creators:
            result.add(CRITICAL, "Document/creationInfo", "creationInfo.creators is empty or missing")
        else:
            has_tool = any(c.startswith("Tool:") for c in creators)
            has_org_rh = "Organization: Red Hat" in creators

            if not has_tool:
                result.add(
                    MAJOR,
                    "Document/creationInfo",
                    "creationInfo.creators must include a 'Tool: <name> <version>' entry",
                )
            else:
                # Check if tool has a version
                tool_entries = [c for c in creators if c.startswith("Tool:")]
                for tool_entry in tool_entries:
                    tool_value = tool_entry[len("Tool:"):].strip()
                    if not tool_value:
                        result.add(
                            MINOR,
                            "Document/creationInfo",
                            "Tool creator entry is empty — should include tool name and version",
                        )

            if not has_org_rh:
                result.add(
                    CRITICAL,
                    "Document/creationInfo",
                    f"creationInfo.creators must include 'Organization: Red Hat' (required for RTPA2 handling). "
                    f"Found: {creators}",
                )
            else:
                # Check for non-Red Hat organization entries alongside Red Hat
                non_rh_orgs = [
                    c for c in creators if c.startswith("Organization:") and c != "Organization: Red Hat"
                ]
                if non_rh_orgs:
                    result.add(
                        MINOR,
                        "Document/creationInfo",
                        f"Additional organization entries found alongside 'Organization: Red Hat': {non_rh_orgs}",
                    )

    # ---- Relationships ----
    relationships: list[dict] = data.get("relationships", [])
    if not relationships:
        result.add(CRITICAL, "Document/Relationships", "No relationships defined in SBOM")
    else:
        has_describes = any(r.get("relationshipType") == "DESCRIBES" for r in relationships)
        if not has_describes:
            result.add(
                CRITICAL,
                "Document/Relationships",
                "No DESCRIBES relationship found — document must describe its primary artifact",
            )

    # ---- Packages ----
    packages: list[dict] = data.get("packages", [])
    if not packages:
        result.add(CRITICAL, "Packages", "No packages defined in SBOM")
        return

    # Build a set of all SPDX IDs for relationship validation
    all_ids = {pkg.get("SPDXID") for pkg in packages}

    # Detect SBOM type based on purl namespaces present
    srpm_id = None
    binary_rpm_ids: list[str] = []
    has_upstream_source = False

    # Track deduplication: only report PURL issues once per purl string
    seen_purls: set[str] = set()

    for pkg in packages:
        loc = _pkg_location(pkg)

        # Mandatory fields
        if not pkg.get("SPDXID"):
            result.add(CRITICAL, "Packages", "Package missing SPDXID", loc)

        if not pkg.get("name"):
            result.add(MAJOR, "Packages", "Package missing 'name' field", loc)

        if not pkg.get("versionInfo"):
            result.add(MINOR, "Packages", "Package missing 'versionInfo' field", loc)

        if not pkg.get("downloadLocation"):
            result.add(MAJOR, "Packages", "Package missing 'downloadLocation' field", loc)

        # Supplier check — packages identified by pkg:rpm/redhat/* must have Red Hat as supplier
        supplier = pkg.get("supplier", "")
        ext_refs = pkg.get("externalRefs", [])
        all_purls = [
            r.get("referenceLocator", "")
            for r in ext_refs
            if r.get("referenceType") == "purl" and r.get("referenceCategory") == "PACKAGE-MANAGER"
        ]
        cpes = [r for r in ext_refs if "cpe" in r.get("referenceType", "").lower()]
        is_redhat_rpm = any("pkg:rpm/redhat/" in p for p in all_purls)
        is_redhat_oci = any("pkg:oci/" in p and "redhat" in p for p in all_purls)

        if (is_redhat_rpm or is_redhat_oci) and supplier and supplier != "Organization: Red Hat":
            result.add(
                MAJOR,
                "Packages",
                f"Supplier is {supplier!r} — expected 'Organization: Red Hat' for Red Hat-distributed packages",
                loc,
            )
        elif not is_redhat_rpm and not is_redhat_oci and not cpes:
            # For non-Red Hat packages, flag if supplier is wrong Org (fedora etc) but not NOASSERTION
            if supplier and supplier.startswith("Organization:") and supplier != "Organization: Red Hat":
                result.add(
                    MAJOR,
                    "Packages",
                    f"Supplier is {supplier!r} — expected 'Organization: Red Hat' for Red Hat-distributed packages",
                    loc,
                )

        # License
        has_license = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
        if not has_license:
            result.add(MINOR, "Packages", "Package has neither licenseConcluded nor licenseDeclared", loc)

        # External references (purls)
        ext_refs = pkg.get("externalRefs", [])
        purls = [
            r.get("referenceLocator", "")
            for r in ext_refs
            if r.get("referenceType") == "purl" and r.get("referenceCategory") == "PACKAGE-MANAGER"
        ]
        cpe_refs = [r for r in ext_refs if "cpe" in r.get("referenceType", "").lower()]
        is_product_component = bool(cpe_refs) and not purls

        if not purls and not is_product_component:
            result.add(
                MAJOR,
                "Packages",
                "Package has no purl in externalRefs (PACKAGE-MANAGER category) — purl required for all non-product packages",
                loc,
            )
        else:
            for purl in purls:
                if purl not in seen_purls:
                    seen_purls.add(purl)
                    parsed = validate_purl(purl, result, loc)
                    if parsed:
                        ptype = parsed["type"].lower()
                        if ptype == "rpm":
                            fname = pkg.get("packageFileName", "")
                            if fname.endswith(".src.rpm"):
                                srpm_id = pkg.get("SPDXID")
                            elif any(
                                fname.endswith(f".{a}.rpm")
                                for a in ("x86_64", "aarch64", "ppc64le", "s390x", "i686", "noarch")
                            ):
                                binary_rpm_ids.append(pkg.get("SPDXID", ""))
                        elif ptype == "generic":
                            has_upstream_source = True

        # Checksums — required for RPMs and OCI images
        checksums = pkg.get("checksums", [])
        fname = pkg.get("packageFileName", "")
        is_rpm = fname.endswith(".rpm") if fname else any(
            "rpm" in (r.get("referenceLocator", "")) for r in ext_refs
        )
        is_oci = any(
            "oci" in (r.get("referenceLocator", "")[:7]) for r in ext_refs
            if r.get("referenceType") == "purl"
        )
        if (is_rpm or is_oci) and not checksums:
            result.add(MINOR, "Packages", "RPM/OCI package is missing checksums", loc)
        elif checksums:
            has_sha256 = any(c.get("algorithm", "").upper() == "SHA256" for c in checksums)
            if not has_sha256 and (is_rpm or is_oci):
                result.add(
                    MINOR,
                    "Packages",
                    "SHA256 checksum not found in checksums list",
                    loc,
                )

    # ---- Relationship completeness checks ----
    if srpm_id:
        srpm_rels = [
            r for r in relationships
            if r.get("relatedSpdxElement") == srpm_id and r.get("relationshipType") == "GENERATED_FROM"
        ]
        if not srpm_rels:
            result.add(
                MINOR,
                "Relationships",
                f"SRPM {srpm_id!r} has no binary RPMs with GENERATED_FROM relationship pointing to it",
            )

        # Check that SRPM contains source archives (CONTAINS relationships)
        srpm_contains = [
            r for r in relationships
            if r.get("spdxElementId") == srpm_id and r.get("relationshipType") == "CONTAINS"
        ]
        if not srpm_contains and has_upstream_source:
            result.add(
                MINOR,
                "Relationships",
                f"SRPM {srpm_id!r} has upstream source packages but no CONTAINS relationships to them",
            )


# ---------------------------------------------------------------------------
# CycloneDX 1.6 validation
# ---------------------------------------------------------------------------

_CDX_TOOL_KEY = "tools"


def validate_cyclonedx(data: dict, result: ValidationResult) -> None:
    result.format = "CycloneDX"

    if data.get("bomFormat") != "CycloneDX":
        result.add(CRITICAL, "Document", f"bomFormat must be 'CycloneDX', got {data.get('bomFormat')!r}")

    spec = data.get("specVersion", "")
    if spec != "1.6":
        result.add(
            MAJOR,
            "Document",
            f"specVersion should be '1.6' (current guideline version), got {spec!r}",
        )

    if not data.get("version"):
        result.add(MINOR, "Document", "Document 'version' field is missing (recommended)")

    serial = data.get("serialNumber", "")
    if not serial:
        result.add(MINOR, "Document", "serialNumber is missing")
    elif not serial.startswith("urn:uuid:"):
        result.add(MINOR, "Document", f"serialNumber should be a URN UUID (urn:uuid:...), got {serial!r}")

    # ---- metadata ----
    metadata = data.get("metadata")
    if not metadata:
        result.add(CRITICAL, "Document/metadata", "metadata block is missing")
        return

    result.name = (metadata.get("component") or {}).get("name", "")

    ts = metadata.get("timestamp", "")
    if not ts:
        result.add(MAJOR, "Document/metadata", "metadata.timestamp is missing")
    elif not _UTC_TIMESTAMP_RE.match(ts):
        result.add(
            MAJOR,
            "Document/metadata",
            f"metadata.timestamp must be in YYYY-MM-DDThh:mm:ssZ format, got {ts!r}",
        )

    # Supplier
    supplier = metadata.get("supplier") or {}
    supplier_name = supplier.get("name", "")
    if not supplier_name:
        result.add(
            MAJOR,
            "Document/metadata",
            "metadata.supplier is missing — must identify Red Hat as the supplier",
        )
    elif "Red Hat" not in supplier_name:
        result.add(
            MAJOR,
            "Document/metadata",
            f"metadata.supplier.name should be 'Red Hat', got {supplier_name!r}",
        )

    # Tools
    tools_block = metadata.get("tools")
    if not tools_block:
        result.add(
            MAJOR,
            "Document/metadata",
            "metadata.tools is missing — tool information is required",
        )
    else:
        # Tools may be a list (CDX <1.5) or a dict with 'components'
        if isinstance(tools_block, dict):
            tool_components = tools_block.get("components", [])
        else:
            tool_components = tools_block
        if not tool_components:
            result.add(MAJOR, "Document/metadata", "metadata.tools is empty — at least one tool must be listed")

    # Main component
    main_component = metadata.get("component")
    if not main_component:
        result.add(MAJOR, "Document/metadata", "metadata.component is missing — root component not defined")
    else:
        if not main_component.get("purl"):
            result.add(
                MAJOR,
                "Document/metadata",
                "metadata.component is missing a 'purl' identifier",
            )
        else:
            validate_purl(main_component["purl"], result, "metadata.component")

    # ---- components ----
    components: list[dict] = data.get("components", [])
    if not components:
        result.add(MINOR, "Components", "No components listed in SBOM")
        return

    seen_purls: set[str] = set()

    for comp in components:
        bom_ref = comp.get("bom-ref", comp.get("name", "?"))
        loc = f"component:{bom_ref}"

        if not comp.get("type"):
            result.add(MAJOR, "Components", "Component missing 'type' field", loc)

        if not comp.get("name"):
            result.add(MAJOR, "Components", "Component missing 'name' field", loc)

        if not comp.get("version"):
            result.add(MINOR, "Components", "Component missing 'version' field", loc)

        purl = comp.get("purl", "")
        if not purl:
            result.add(MAJOR, "Components", "Component missing 'purl' identifier", loc)
        elif purl not in seen_purls:
            seen_purls.add(purl)
            validate_purl(purl, result, loc)

        # Supplier / manufacturer
        if not comp.get("supplier") and not comp.get("manufacturer"):
            result.add(MINOR, "Components", "Component has no 'supplier' or 'manufacturer' field", loc)

        # Hashes
        hashes = comp.get("hashes", [])
        purl_type = (parse_purl(purl) or {}).get("type", "").lower() if purl else ""
        if purl_type in ("rpm", "oci") and not hashes:
            result.add(MINOR, "Components", "RPM/OCI component is missing hashes", loc)

    # ---- dependencies ----
    dependencies = data.get("dependencies", [])
    if not dependencies:
        result.add(
            INFO,
            "Dependencies",
            "No dependency graph defined — consider adding top-level dependencies block",
        )


# ---------------------------------------------------------------------------
# Auto-detect format and dispatch
# ---------------------------------------------------------------------------


def load_sbom(path: str) -> dict:
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as fh:
        return json.load(fh)


def detect_format(data: dict) -> str:
    if "spdxVersion" in data:
        return "spdx"
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    return "unknown"


def validate(path: str) -> ValidationResult:
    result = ValidationResult()
    try:
        data = load_sbom(path)
    except Exception as exc:
        result.add(CRITICAL, "Parse", f"Failed to load SBOM: {exc}")
        result.parse_failed = True
        return result

    fmt = detect_format(data)
    if fmt == "spdx":
        validate_spdx(data, result)
    elif fmt == "cyclonedx":
        validate_cyclonedx(data, result)
    else:
        result.add(CRITICAL, "Parse", "Could not detect SBOM format (expected SPDX or CycloneDX JSON)")
        result.parse_failed = True

    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _c(severity: str, colors: dict[str, str] | None = None) -> str:
    mapping = _SEVERITY_COLORS if colors is None else colors
    return mapping.get(severity, "")


def _reset(colors: dict[str, str] | None = None) -> str:
    mapping = _SEVERITY_COLORS if colors is None else colors
    return mapping["RESET"]


def print_report(
    result: ValidationResult,
    path: str,
    use_color: bool = True,
    score: int | None = None,
    counts: dict[str, int] | None = None,
    unique_counts: dict[str, int] | None = None,
) -> None:
    colors = dict(_SEVERITY_COLORS)
    if not use_color:
        for k in colors:
            colors[k] = ""

    bold = colors["BOLD"]
    reset = colors["RESET"]
    green = colors["GREEN"]
    red = colors["RED"]

    score = score if score is not None else result.compute_score()
    counts = counts if counts is not None else result.counts()

    print(f"\n{bold}SBOM Compliance Report{reset}")
    print(f"{'─' * 60}")
    print(f"  File   : {path}")
    print(f"  Format : {result.format}")
    print(f"  Name   : {result.name or '(unknown)'}")
    print(f"{'─' * 60}")

    # Sort findings: CRITICAL first, then MAJOR, MINOR, INFO
    sorted_findings = sorted(
        result.findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )

    if not sorted_findings:
        print(f"\n  {green}No issues found! Fully compliant.{reset}\n")
    else:
        current_sev = None
        for finding in sorted_findings:
            if finding.severity != current_sev:
                current_sev = finding.severity
                print(f"\n  {bold}{_c(current_sev, colors)}{current_sev}{reset}")
            color = _c(finding.severity, colors)

            if finding.count > 1:
                count_note = f" {bold}(×{finding.count}){reset}"
                if finding.sample_locations:
                    samples = ", ".join(finding.sample_locations[:2])
                    if finding.count > len(finding.sample_locations):
                        samples += f", … +{finding.count - len(finding.sample_locations)} more"
                    loc_str = f"  [e.g. {samples}]"
                else:
                    loc_str = ""
            else:
                count_note = ""
                loc_str = f"  [{finding.location}]" if finding.location else ""

            print(f"    {color}●{reset} {finding.category}{count_note}{loc_str}:")
            print(f"      {finding.message}")

    ucounts = unique_counts if unique_counts is not None else result.unique_counts()
    print(f"\n{'─' * 60}")
    print(f"  Summary  (unique issue types / total occurrences):")
    print(f"    {_c(CRITICAL, colors)}{bold}CRITICAL{reset}: {ucounts[CRITICAL]} types / {counts[CRITICAL]} occurrences")
    print(f"    {_c(MAJOR, colors)}{bold}MAJOR{reset}   : {ucounts[MAJOR]} types / {counts[MAJOR]} occurrences")
    print(f"    {_c(MINOR, colors)}{bold}MINOR{reset}   : {ucounts[MINOR]} types / {counts[MINOR]} occurrences")
    print(f"    {_c(INFO, colors)}{bold}INFO{reset}    : {ucounts[INFO]} types / {counts[INFO]} occurrences")

    bar_len = 40
    filled = round((score / 10) * bar_len)
    bar_color = green if score >= 8 else (_c(MAJOR, colors) if score >= 5 else red)
    bar = bar_color + "█" * filled + reset + "░" * (bar_len - filled)
    print(f"\n  {bold}Compliance Score: {bar_color}{score}/10{reset}")
    print(f"  [{bar}]")

    if score >= 8:
        label = f"{green}COMPLIANT{reset}"
    elif score >= 5:
        label = f"{_c(MAJOR, colors)}PARTIALLY COMPLIANT{reset}"
    else:
        label = f"{red}NON-COMPLIANT{reset}"
    print(f"  Status: {bold}{label}")
    print(f"{'─' * 60}\n")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("sbom", help="Path to SBOM file (.json or .json.gz)")
    parser.add_argument(
        "--no-color", action="store_true", help="Disable ANSI color output"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output findings as JSON (implies --no-color)"
    )
    parser.add_argument(
        "--min-severity",
        choices=[CRITICAL, MAJOR, MINOR, INFO],
        default=MINOR,
        help="Only show findings at or above this severity (default: MINOR)",
    )
    args = parser.parse_args()

    result = validate(args.sbom)

    # Compute score and counts before any filtering so they reflect all findings
    final_score = result.compute_score()
    counts_before = result.counts()
    unique_counts_before = result.unique_counts()

    # Filter displayed findings by min severity
    min_level = _SEVERITY_ORDER.get(args.min_severity, 2)
    result.findings = [
        f for f in result.findings if _SEVERITY_ORDER.get(f.severity, 99) <= min_level
    ]

    if args.json:
        output = {
            "file": args.sbom,
            "format": result.format,
            "name": result.name,
            "score": final_score,
            "counts_total": counts_before,
            "counts_unique": unique_counts_before,
            "findings": [
                {
                    "severity": f.severity,
                    "category": f.category,
                    "location": f.location,
                    "message": f.message,
                    "count": f.count,
                    "sample_locations": f.sample_locations,
                }
                for f in result.findings
            ],
        }
        print(json.dumps(output, indent=2))
    else:
        print_report(
            result,
            args.sbom,
            use_color=not args.no_color,
            score=final_score,
            counts=counts_before,
            unique_counts=unique_counts_before,
        )

    if result.parse_failed:
        return 3

    if final_score >= 8:
        return 0
    elif final_score >= 5:
        return 1
    else:
        return 2


if __name__ == "__main__":
    sys.exit(main())
