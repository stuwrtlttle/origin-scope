"""Vulnerability scanner report ingestion and Red Hat Catalog inventory retrieval.

This module deliberately preserves scanner assertions separately from catalog
inventory evidence.  A match against a published image RPM manifest proves
image membership; it does not prove source-file or base-image origin.
"""

import csv
import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


PYXIS_URL = "https://catalog.redhat.com/api/containers/v1"
CATALOG_REGISTRY = "registry.access.redhat.com"
AUTHENTICATED_REGISTRY = "registry.redhat.io"
PODMAN_TIMEOUT_SECONDS = 300
SUPPORTED_REGISTRIES = {"registry.access.redhat.com", "registry.redhat.io"}
BLACKDUCK_REQUIRED_COLUMNS = {
    "Project id", "Project name", "Component name", "Component origin name",
    "Vulnerability id", "Security Risk", "Remediation status",
}
IMAGE_COLUMNS = (
    "Container image", "Container Image", "Image", "Image name", "Image Name",
    "Image reference", "Image Reference", "Image URI", "Image URI/Tag",
    "Target", "ArtifactName", "Artifact Name", "Tag", "imageName", "Image Name",
    "image", "image_name", "projectName", "Project Name",
)
CVE_COLUMNS = (
    "Vulnerability id", "CVE", "CVEs", "CVE ID", "CVE IDs", "Vulnerability ID",
    "VulnerabilityID", "Vulnerability", "ID", "Name", "Issue ID", "ISSUE ID", "Associated CVEs",
)
COMPONENT_COLUMNS = (
    "Component name", "Package", "PkgName", "Package Name", "Source Package",
    "Library", "FeatureName", "Feature", "Software", "Component", "package", "packageName", "Name",
)
VERSION_COLUMNS = (
    "Component version name", "Version", "InstalledVersion", "Installed Version",
    "Installed", "FeatureVersion", "CurrentVersion", "Component Version", "packageVersion", "version",
)
SEVERITY_COLUMNS = ("Security Risk", "Severity", "severity", "CVSS Severity", "Risk")
STATUS_COLUMNS = ("Remediation status", "Status", "Fixable", "Fixed By", "CVE Fixed In")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
ARCHITECTURES = {"amd64", "arm64", "ppc64le", "s390x"}
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
GRYPE_COLUMNS = ("NAME", "INSTALLED", "FIXED IN", "TYPE", "VULNERABILITY", "SEVERITY", "EPSS", "RISK")
RATIONALE_RULES_PATH = Path(__file__).with_name("scanner_rationale_rules.json")
SCANNER_RATIONALE_RULES = json.loads(RATIONALE_RULES_PATH.read_text(encoding="utf-8"))


class ScannerInputError(ValueError):
    """The scanner input cannot be safely correlated with an image."""


@dataclass(frozen=True)
class ScannerFinding:
    cve_id: str
    component_name: str
    component_version: str
    component_origin: str
    scanner_match_type: str
    scanner_status: str
    scanner_severity: str
    image_reference: str
    raw: dict
    scanner_name: str = "unknown"


@dataclass(frozen=True)
class ImageSubject:
    requested_reference: str
    resolved_reference: str
    registry: str
    repository: str
    tag: str | None
    digest: str
    architecture: str
    catalog_image_id: str
    catalog_url: str
    rpm_manifest_url: str
    advisory: str | None

    def evidence(self):
        return asdict(self)


@dataclass(frozen=True)
class ImageCandidate:
    """A public Catalog image inferred from scanner-report evidence.

    A candidate is deliberately not an assertion that the scanner ran against
    that image.  It is a ranked, inspectable suggestion that the caller must
    explicitly confirm before the Catalog RPM manifest is used for analysis.
    """

    reference: str
    repository: str
    tag: str
    architecture: str
    brew_package: str
    brew_build: str
    advisory: str | None
    catalog_url: str
    score: int
    reasons: tuple[str, ...]

    def evidence(self):
        return {**asdict(self), "reasons": list(self.reasons)}


def _field(row, name):
    return (row.get(name) or "").strip()


def _normal(value):
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _field_any(row, names):
    values = {_normal(str(key)): str(value or "").strip() for key, value in row.items() if key is not None}
    for name in names:
        value = values.get(_normal(name), "")
        if value:
            return value
    return ""


def _cves(value):
    return sorted({match.upper() for match in CVE_RE.findall(str(value or ""))})


def _image_value(value):
    value = str(value or "").strip()
    return value.removeprefix("docker-image|")


def _read_csv(path):
    """Read comma, semicolon, or tab-delimited scanner output."""
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        sample = handle.read(8192)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(handle, dialect=dialect)
        return [{key: value for key, value in row.items() if key is not None} for row in reader], reader.fieldnames or []


def _detect_csv_scanner(columns):
    normalized = {_normal(column) for column in columns if column}
    if {_normal(column) for column in BLACKDUCK_REQUIRED_COLUMNS}.issubset(normalized):
        return "black-duck"
    if {"cluster", "namespace", "deployment", "image", "component", "cve"}.issubset(normalized):
        return "rhacs"
    if "vulnerabilityid" in normalized and ("pkgname" in normalized or "installedversion" in normalized):
        return "trivy"
    if "pluginid" in normalized or "pluginoutput" in normalized:
        return "nessus"
    if "qid" in normalized or "associatedcves" in normalized:
        return "qualys"
    if "sourcepackage" in normalized or "cvefixedin" in normalized:
        return "prisma"
    if "issueid" in normalized or "issuestatus" in normalized:
        return "snyk"
    if "featureversion" in normalized or "featurename" in normalized:
        return "clair"
    if {"name", "installed", "fixedin", "type", "vulnerability", "severity"}.issubset(normalized):
        return "grype"
    if "package" in normalized and ("vulnerabilityid" in normalized or "cve" in normalized or "id" in normalized):
        return "anchore"
    return "generic"


def _scanner_component(row):
    """Match rh-vex-checker's Black Duck normalization for package identity."""
    name = _field(row, "Component name")
    version = _field(row, "Component version name")
    origin = _field(row, "Component origin name")
    origin_id = _field(row, "Component origin id")
    origin_version = _field(row, "Component origin version name")
    if origin.lower() in {"redhat", "red hat", "rocky", "centos", "crates", "pypi"} and "/" in origin_id:
        name, version, *_ = origin_id.split("/")
    elif origin_version:
        version = origin_version
    if "/" in version and version.rsplit("/", 1)[-1] in {"aarch64", "i386", "i686", "noarch", "ppc64le", "s390x", "x86_64"}:
        version = version.rsplit("/", 1)[0]
    return name, version, origin


def parse_blackduck_csv(path):
    """Parse supported Black Duck/Black Dot CSV without discarding raw rows."""
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = {column.strip() for column in (reader.fieldnames or []) if column}
        if not BLACKDUCK_REQUIRED_COLUMNS.issubset(columns):
            missing = ", ".join(sorted(BLACKDUCK_REQUIRED_COLUMNS - columns))
            raise ScannerInputError(f"CSV is not a supported Black Duck vulnerability status report; missing: {missing}.")
        findings = []
        for row in reader:
            raw = {key: value for key, value in row.items() if key is not None}
            cves = _cves(_field(raw, "Vulnerability id"))
            if not cves:
                continue
            component, version, origin = _scanner_component(raw)
            if not component:
                continue
            image_reference = next((_field(raw, column) for column in IMAGE_COLUMNS if _field(raw, column)), "")
            for cve_id in cves:
                findings.append(ScannerFinding(
                    cve_id=cve_id,
                    component_name=component,
                    component_version=version,
                    component_origin=origin,
                    scanner_match_type=_field(raw, "Match type") or "unknown",
                    scanner_status=_field(raw, "Remediation status") or "unknown",
                    scanner_severity=_field(raw, "Security Risk") or "unknown",
                    image_reference=image_reference,
                    raw=raw,
                    scanner_name="black-duck",
                ))
    if not findings:
        raise ScannerInputError("No CVE findings were found in the Black Duck CSV.")
    return findings


def _generic_findings(rows, scanner_name):
    findings = []
    for raw in rows:
        cves = _cves(_field_any(raw, CVE_COLUMNS))
        if not cves:
            continue
        component = _field_any(raw, COMPONENT_COLUMNS) or "unknown"
        version = _field_any(raw, VERSION_COLUMNS)
        origin = _field_any(raw, ("Component origin name", "Origin", "Package Type", "Type"))
        image_reference = _image_value(_field_any(raw, IMAGE_COLUMNS))
        for cve_id in cves:
            findings.append(ScannerFinding(
                cve_id=cve_id, component_name=component, component_version=version,
                component_origin=origin, scanner_match_type=_field_any(raw, ("Match type", "Match Type", "Type", "Plugin ID")) or scanner_name,
                scanner_status=_field_any(raw, STATUS_COLUMNS) or "reported",
                scanner_severity=_field_any(raw, SEVERITY_COLUMNS) or "unknown",
                image_reference=image_reference, raw=raw, scanner_name=scanner_name,
            ))
    return findings


def _simple_cve_image_csv(path):
    """Support cve-analyser's no-header `CVE,image-or-package` input."""
    with Path(path).open("r", encoding="utf-8-sig", newline="") as handle:
        sample = handle.read(8192)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
        except csv.Error:
            dialect = csv.excel
        findings = []
        for number, row in enumerate(csv.reader(handle, dialect=dialect), start=1):
            if len(row) < 2 or not _cves(row[0]):
                continue
            for cve_id in _cves(row[0]):
                value = row[1].strip()
                findings.append(ScannerFinding(
                    cve_id=cve_id, component_name="unknown", component_version="", component_origin="",
                    scanner_match_type="cve-analyser input", scanner_status="reported", scanner_severity="unknown",
                    image_reference=value, raw={"row": number, "cve": row[0], "image_or_package": value},
                    scanner_name="cve-analyser",
                ))
    return findings


def grype_text_rows(path):
    """Parse Grype's aligned terminal table, including colorized output.

    Grype's default human-readable output is whitespace-aligned, rather than
    delimited.  Slice each row using the header positions so an empty ``FIXED
    IN`` field and multi-value fixes do not shift the remaining columns.
    """
    lines = [ANSI_ESCAPE_RE.sub("", line.rstrip("\n"))
             for line in Path(path).read_text(encoding="utf-8-sig", errors="replace").splitlines()]
    header_index = next((index for index, line in enumerate(lines)
                         if "VULNERABILITY" in line and "INSTALLED" in line and "SEVERITY" in line), None)
    if header_index is None:
        raise ScannerInputError("Text report is not a recognized Grype findings table.")
    header = lines[header_index]
    positions = [(label, header.find(label)) for label in GRYPE_COLUMNS if header.find(label) >= 0]
    required = {"NAME", "INSTALLED", "TYPE", "VULNERABILITY", "SEVERITY"}
    if not required.issubset({label for label, _ in positions}):
        raise ScannerInputError("Grype findings table is missing required columns.")
    positions.sort(key=lambda item: item[1])
    rows = []
    for line in lines[header_index + 1:]:
        if not line.strip():
            continue
        row = {
            label: line[start:positions[index + 1][1] if index + 1 < len(positions) else None].strip()
            for index, (label, start) in enumerate(positions)
        }
        if _cves(row.get("VULNERABILITY", "")):
            rows.append(row)
    if not rows:
        raise ScannerInputError("No CVE findings were found in the Grype text report.")
    return rows


def parse_grype_text(path):
    """Normalize Grype terminal output into the scanner finding model."""
    findings = []
    for raw in grype_text_rows(path):
        for cve_id in _cves(raw["VULNERABILITY"]):
            findings.append(ScannerFinding(
                cve_id=cve_id,
                component_name=raw["NAME"],
                component_version=raw["INSTALLED"],
                component_origin=raw.get("TYPE", ""),
                scanner_match_type="grype table",
                scanner_status="fix available" if raw.get("FIXED IN") else "reported",
                scanner_severity=raw.get("SEVERITY", "unknown") or "unknown",
                image_reference="",
                raw=raw,
                scanner_name="grype",
            ))
    return findings


def _json_image(data):
    if not isinstance(data, dict):
        return ""
    source = data.get("source", {}) if isinstance(data.get("source"), dict) else {}
    target = source.get("target", {}) if isinstance(source.get("target"), dict) else {}
    return _image_value(_field_any(data, IMAGE_COLUMNS) or target.get("userInput", ""))


def _json_findings(path):
    data = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(data, (dict, list)):
        raise ScannerInputError("JSON vulnerability report must contain an object or list.")
    root = data if isinstance(data, dict) else {}
    image = _json_image(root)
    findings = []

    # Trivy JSON: one target with a list of package vulnerabilities.
    for result in root.get("Results", []) if isinstance(root.get("Results"), list) else []:
        target_image = _image_value(result.get("Target", "")) or image
        for item in result.get("Vulnerabilities", []) or []:
            raw = dict(item)
            raw.setdefault("Target", target_image)
            raw.setdefault("Package", item.get("PkgName", ""))
            raw.setdefault("Version", item.get("InstalledVersion", ""))
            findings.extend(_generic_findings([raw], "trivy"))

    # Grype JSON retains the matcher evidence needed to explain *why* its
    # vulnerability database associated a CVE with an artifact.
    for match in root.get("matches", []) if isinstance(root.get("matches"), list) else []:
        vulnerability = match.get("vulnerability", {}) if isinstance(match.get("vulnerability"), dict) else {}
        artifact = match.get("artifact", {}) if isinstance(match.get("artifact"), dict) else {}
        raw = dict(vulnerability)
        raw.update({
            "Package": artifact.get("name", ""), "Version": artifact.get("version", ""), "Image": image,
            "Grype match details": match.get("matchDetails", []),
            "Grype namespace": vulnerability.get("namespace", ""),
            "Grype data source": vulnerability.get("dataSource", ""),
            "Grype fix": vulnerability.get("fix", {}),
        })
        findings.extend(_generic_findings([raw], "grype"))

    # Snyk and other JSON reports commonly expose a top-level vulnerabilities list.
    for item in root.get("vulnerabilities", []) if isinstance(root.get("vulnerabilities"), list) else []:
        if not isinstance(item, dict):
            continue
        raw = dict(item)
        identifiers = item.get("identifiers", {})
        if isinstance(identifiers, dict):
            raw["CVEs"] = " ".join(identifiers.get("CVE", []) or [])
        raw.setdefault("Package", item.get("packageName", item.get("package", "")))
        raw.setdefault("Version", item.get("version", ""))
        raw.setdefault("Image", image)
        findings.extend(_generic_findings([raw], "snyk"))

    # A generic list/object is useful for scanners that emit normalized JSON.
    entries = data if isinstance(data, list) else root.get("findings", root.get("results", []))
    if isinstance(entries, list):
        for item in entries:
            if isinstance(item, dict):
                raw = dict(item)
                raw.setdefault("Image", image)
                findings.extend(_generic_findings([raw], "generic-json"))
    if not findings:
        raise ScannerInputError("No CVE findings were found in the JSON vulnerability report.")
    return findings


def parse_vulnerability_report(path):
    """Normalize common scanner CSV, JSON, and Grype text formats."""
    path = Path(path)
    if path.suffix.lower() == ".json":
        return _json_findings(path)
    if path.suffix.lower() in {".out", ".txt"}:
        return parse_grype_text(path)
    if path.suffix.lower() != ".csv":
        raise ScannerInputError("Use a CSV, JSON, or supported text vulnerability report.")
    rows, columns = _read_csv(path)
    scanner_name = _detect_csv_scanner(columns)
    if scanner_name == "black-duck":
        return parse_blackduck_csv(path)
    findings = _generic_findings(rows, scanner_name)
    if not findings:
        findings = _simple_cve_image_csv(path)
    if not findings:
        raise ScannerInputError("No CVE findings were found. Supported formats include Black Duck, RHACS, Trivy, Clair, Anchore/Grype, Prisma, Snyk, Nessus, Qualys, CVE,image CSV, and Grype text output.")
    return findings


def choose_image_reference(findings, supplied_reference=""):
    """Use an explicit image first; otherwise require one unambiguous CSV value."""
    supplied_reference = supplied_reference.strip()
    candidates = {finding.image_reference for finding in findings if finding.image_reference}
    if supplied_reference:
        return supplied_reference
    if len(candidates) == 1:
        return candidates.pop()
    if not candidates:
        raise ScannerInputError("Provide the scanned container image; this CSV has no recognized image column.")
    raise ScannerInputError("CSV contains findings for multiple images; provide one CSV per image or an explicit image reference.")


def _scan_name_hint(path):
    """Extract a Brew package and build/tag hint from a scanner report name."""
    name = Path(path).stem
    name = re.sub(r"(?i)(?:[_-](?:grype|trivy|clair|anchore|scanner|scan|report))+$", "", name)
    name = re.sub(r"(?:[_-])\d{4}-\d{2}-\d{2}$", "", name)
    match = re.match(r"^(?P<package>.+?)[_-](?P<build>v\d[0-9A-Za-z.+_-]*)$", name)
    if not match:
        return "", ""
    return match.group("package"), match.group("build")


def _catalog_images(filter_expression, fetch_json):
    query = urllib.parse.urlencode({"filter": filter_expression, "page_size": "500"})
    data = fetch_json(f"{PYXIS_URL}/images?{query}")
    return data.get("data", []) if isinstance(data, dict) else []


def _catalog_repository_images(repository, architecture, fetch_json):
    """Fetch one known public repository, including images without Brew data."""
    path = urllib.parse.quote(repository, safe="")
    query = urllib.parse.urlencode({"filter": f'architecture=="{architecture}"', "page_size": "500"})
    data = fetch_json(
        f"{PYXIS_URL}/repositories/registry/{urllib.parse.quote(CATALOG_REGISTRY, safe='')}"
        f"/repository/{path}/images?{query}"
    )
    return data.get("data", []) if isinstance(data, dict) else []


def _rhel_major_from_findings(findings):
    """Return the dominant RHEL major evidenced by RPM versions in a scan."""
    counts = {}
    for finding in findings:
        match = re.search(r"\.el(\d+)(?:[_.]|$)", finding.component_version or "")
        if match:
            major = match.group(1)
            counts[major] = counts.get(major, 0) + 1
    if not counts:
        return ""
    major, count = max(counts.items(), key=lambda item: item[1])
    return major if count >= 3 else ""


def _rhel_repository_variants(repositories, rhel_major):
    if not rhel_major:
        return []
    variants = set()
    for repository in repositories:
        if re.search(r"rhel\d+", repository):
            variants.add(re.sub(r"rhel\d+", f"rhel{rhel_major}", repository))
    return sorted(variants)


def _version_key(value):
    """A small, dependency-free key for Red Hat's vX.Y.Z-build style tags."""
    parts = [int(item) for item in re.findall(r"\d+", value or "")[:4]]
    return tuple(parts + [0] * (4 - len(parts)))


def _candidate_from_catalog_image(image, architecture, package_hint, build_hint, rhel_major=""):
    brew = image.get("brew") or {}
    brew_package = brew.get("package", "") or package_hint
    brew_build = brew.get("build", "")
    best = None
    for entry in image.get("repositories", []) or []:
        repository = entry.get("repository", "")
        if not repository or not entry.get("published", True):
            continue
        tags = [item.get("name", "") for item in entry.get("tags", []) or []]
        build_tag = brew_build.removeprefix(f"{brew_package}-") if brew_build else ""
        exact_tag = next((tag for tag in tags if tag == build_hint), "")
        version_tag = next((tag for tag in tags if build_hint and tag == build_hint.rsplit("-", 1)[0]), "")
        semantic_tag = next((tag for tag in tags if re.fullmatch(r"v\d+(?:\.\d+)+(?:-\d+(?:\.\d+)*)?", tag)), "")
        tag = exact_tag or version_tag or next((tag for tag in tags if tag == build_tag), "") or semantic_tag or next((tag for tag in tags if tag), "")
        if not tag:
            continue
        reasons = []
        score = 20
        if brew_package == package_hint:
            score += 25
            reasons.append(f"Brew package matches report name: {brew_package}" if brew.get("package")
                           else f"Repository was derived from matching Brew package: {brew_package}")
        if brew_build == f"{package_hint}-{build_hint}":
            score += 55
            reasons.append(f"Brew build matches report name: {brew_build}")
        elif exact_tag:
            score += 35
            reasons.append(f"Published tag matches report version: {exact_tag}")
        elif version_tag:
            score += 25
            reasons.append(f"Published tag matches report version: {version_tag}")
        else:
            candidate_tag = build_tag or tag
            report_version, candidate_version = _version_key(build_hint), _version_key(candidate_tag)
            if report_version and candidate_version and report_version[0] == candidate_version[0]:
                distance = sum(abs(left - right) for left, right in zip(report_version[1:], candidate_version[1:]))
                score += max(0, 15 - min(distance, 15))
            reasons.append(f"Package matches; closest published build is {candidate_tag}, not {build_hint}")
        if rhel_major and f"rhel{rhel_major}" in repository:
            score += 20
            reasons.append(f"Scanner RPM versions are predominantly RHEL {rhel_major}")
        elif rhel_major:
            reasons.append(f"Scanner RPM versions are predominantly RHEL {rhel_major}; repository is not RHEL {rhel_major}")
        if not brew_build:
            brew_build = f"{package_hint}-{tag}"
        candidate = ImageCandidate(
            reference=f"{CATALOG_REGISTRY}/{repository}:{tag}",
            repository=repository,
            tag=tag,
            architecture=architecture,
            brew_package=brew_package,
            brew_build=brew_build,
            advisory=entry.get("image_advisory_id") or None,
            catalog_url=_catalog_image_url(CATALOG_REGISTRY, repository, tag, None),
            score=min(score, 100),
            reasons=tuple(reasons),
        )
        if best is None or (candidate.score, candidate.brew_build) > (best.score, best.brew_build):
            best = candidate
    return best


def suggest_image_candidates(report_path, architecture="amd64", fetch_json=None):
    """Return ranked public Catalog candidates for a vulnerability report.

    A scanner-provided fully qualified image remains the strongest candidate,
    but it is still returned for the caller to confirm.  Reports without an
    image are matched from their filename to Catalog Brew package/build data.
    """
    if architecture not in ARCHITECTURES:
        raise ScannerInputError(f"Unsupported architecture: {architecture}.")
    fetch_json = fetch_json or _fetch_json
    findings = parse_vulnerability_report(report_path)
    report_references = sorted({item.image_reference for item in findings if item.image_reference})
    valid_references = []
    for reference in report_references:
        try:
            registry, repository, tag, digest = parse_image_reference(reference)
        except ScannerInputError:
            continue
        if digest:
            valid_references.append(ImageCandidate(
                reference=reference, repository=repository, tag=digest, architecture=architecture,
                brew_package="", brew_build="", advisory=None,
                catalog_url=_catalog_image_url(registry, repository, None, digest), score=100,
                reasons=("Image reference was provided by the scanner report",),
            ))
        else:
            valid_references.append(ImageCandidate(
                reference=reference, repository=repository, tag=tag, architecture=architecture,
                brew_package="", brew_build="", advisory=None,
                catalog_url=_catalog_image_url(registry, repository, tag, None), score=100,
                reasons=("Image reference was provided by the scanner report",),
            ))
    if valid_references:
        return valid_references

    package_hint, build_hint = _scan_name_hint(report_path)
    if not package_hint:
        raise ScannerInputError(
            "The report has no image reference and its filename does not contain a recognizable package/build name. "
            "Enter the scanned Red Hat image explicitly."
        )
    rhel_major = _rhel_major_from_findings(findings)
    package_filter = f'brew.package=="{package_hint}" and architecture=="{architecture}"'
    images = _catalog_images(package_filter, fetch_json)
    repositories = {
        entry.get("repository", "")
        for image in images for entry in image.get("repositories", []) or []
        if entry.get("repository")
    }
    for repository in _rhel_repository_variants(repositories, rhel_major):
        if repository in repositories:
            continue
        try:
            images.extend(_catalog_repository_images(repository, architecture, fetch_json))
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
    candidates = [
        candidate for image in images
        if (candidate := _candidate_from_catalog_image(
            image, architecture, package_hint, build_hint, rhel_major,
        ))
    ]
    candidates.sort(
        key=lambda item: (-item.score, tuple(-part for part in _version_key(item.brew_build)), item.reference)
    )
    if not candidates:
        raise ScannerInputError(
            f"Red Hat Catalog has no published {architecture} image for Brew package {package_hint}. "
            "Enter the scanned image explicitly."
        )
    unique = []
    seen = set()
    for candidate in candidates:
        if candidate.reference not in seen:
            unique.append(candidate)
            seen.add(candidate.reference)
    return unique[:5]


def parse_image_reference(reference):
    """Parse a public Red Hat image reference; a tag or immutable digest is required."""
    value = reference.strip().removeprefix("docker://")
    if not value:
        raise ScannerInputError("A container image reference is required.")
    name, marker, digest = value.partition("@")
    if marker and not re.fullmatch(r"sha256:[0-9a-f]{64}", digest, re.IGNORECASE):
        raise ScannerInputError("Image digest must look like sha256:<64 hexadecimal characters>.")
    pieces = name.split("/")
    if pieces[0] in SUPPORTED_REGISTRIES:
        registry, repository_parts = pieces[0], pieces[1:]
    else:
        registry, repository_parts = CATALOG_REGISTRY, pieces
    if not repository_parts:
        raise ScannerInputError("Image reference must include a repository path.")
    repository = "/".join(repository_parts)
    tag = None
    last = repository_parts[-1]
    if ":" in last:
        image, tag = last.rsplit(":", 1)
        if not image or not tag:
            raise ScannerInputError("Image tag is empty.")
        repository_parts[-1] = image
        repository = "/".join(repository_parts)
    if not digest and not tag:
        raise ScannerInputError("Use an immutable image digest or an explicit image tag; implicit latest is not accepted.")
    return registry, repository, tag, digest or None


def _fetch_json(url):
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "cve-report/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.load(response)


def _catalog_image_url(registry, repository, tag, digest):
    # Pyxis identifies images by the registry/repository pair.  Preserve the
    # registry the caller supplied so a digest is resolved against its actual
    # published location rather than an equivalent-looking repository.
    quoted_registry = urllib.parse.quote(registry, safe="")
    quoted_repository = urllib.parse.quote(repository, safe="")
    if digest:
        return (f"{PYXIS_URL}/images/registry/{quoted_registry}/repository/{quoted_repository}/"
                f"manifest_digest/{urllib.parse.quote(digest, safe='')}")
    return (f"{PYXIS_URL}/repositories/registry/{quoted_registry}/repository/{quoted_repository}/"
            f"tag/{urllib.parse.quote(tag, safe='')}")


def _repository_entry(image, repository, tag):
    for entry in image.get("repositories", []):
        tags = {item.get("name") for item in entry.get("tags", [])}
        if entry.get("repository") == repository and (not tag or tag in tags):
            return entry
    return {}


def resolve_redhat_image(reference, architecture="amd64", fetch_json=_fetch_json):
    """Resolve a public Red Hat image tag/digest to an immutable Catalog image."""
    if architecture not in ARCHITECTURES:
        raise ScannerInputError(f"Unsupported architecture: {architecture}.")
    registry, repository, tag, requested_digest = parse_image_reference(reference)
    data = fetch_json(_catalog_image_url(registry, repository, tag, requested_digest))
    images = data.get("data", []) if isinstance(data, dict) else []
    if not images and isinstance(data, dict) and data.get("_id"):
        images = [data]
    image = next((item for item in images if item.get("architecture") == architecture), None)
    if not image:
        available = sorted({item.get("architecture") for item in images if item.get("architecture")})
        suffix = f" Available: {', '.join(available)}." if available else ""
        raise ScannerInputError(f"Red Hat Catalog has no {architecture} image for {reference}.{suffix}")
    entry = _repository_entry(image, repository, tag)
    digest = image.get("image_id") or entry.get("manifest_schema2_digest")
    image_id = image.get("_id")
    if not digest or not image_id:
        raise ScannerInputError("Catalog image is missing its immutable digest or image identifier.")
    if requested_digest and digest != requested_digest:
        raise ScannerInputError("Catalog returned a different image digest than the requested reference.")
    resolved_reference = f"{registry}/{repository}@{digest}"
    advisory = entry.get("image_advisory_id") or None
    return ImageSubject(
        requested_reference=reference,
        resolved_reference=resolved_reference,
        registry=registry,
        repository=repository,
        tag=tag,
        digest=digest,
        architecture=architecture,
        catalog_image_id=image_id,
        catalog_url=_catalog_image_url(registry, repository, tag, requested_digest),
        rpm_manifest_url=f"{PYXIS_URL}/images/id/{urllib.parse.quote(image_id, safe='')}/rpm-manifest",
        advisory=advisory,
    )


def fetch_rpm_manifest(subject, fetch_json=_fetch_json):
    data = fetch_json(subject.rpm_manifest_url)
    rpms = data.get("rpms", []) if isinstance(data, dict) else []
    if not rpms:
        raise ScannerInputError("Red Hat Catalog returned no RPM inventory for the resolved image.")
    return rpms


def _rpm_nvr(rpm):
    nvra = rpm.get("nvra", "")
    return nvra.rsplit(".", 1)[0] if "." in nvra else nvra


def _source_nvr(rpm):
    """Normalize Catalog's source NEVRA to the NVR BOMQ expects."""
    source_name = rpm.get("srpm_name", "")
    source_nevra = (rpm.get("srpm_nevra", "") or "").removesuffix(".src")
    if not source_name or not source_nevra.startswith(f"{source_name}-"):
        return ""
    version_release = source_nevra[len(source_name) + 1:].split(":", 1)[-1]
    return f"{source_name}-{version_release}" if version_release else ""


def write_catalog_sbom(path, subject, rpms):
    """Write a CycloneDX inventory derived from the catalog RPM manifest.

    The file is a local export of the catalog inventory, not a Red Hat-issued
    SBOM artifact.  Its properties retain the immutable catalog image identity
    and source URL used for the retrieval.
    """
    timestamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    components = []
    for rpm in rpms:
        name = rpm.get("name", "")
        nvr = _rpm_nvr(rpm)
        if not name or not nvr:
            continue
        version = nvr[len(name) + 1:] if nvr.startswith(f"{name}-") else rpm.get("version", "")
        architecture = rpm.get("architecture", "")
        source_name = rpm.get("srpm_name", "")
        source_nvr = _source_nvr(rpm)
        purl = f"pkg:rpm/redhat/{urllib.parse.quote(name, safe='-._~')}@{urllib.parse.quote(version, safe='-._~:+')}"
        if architecture:
            purl += f"?arch={urllib.parse.quote(architecture, safe='-._~') }"
        components.append({
            "type": "library", "name": name, "version": version, "purl": purl,
            "properties": [
                {"name": "redhat:catalog-nvra", "value": rpm.get("nvra", "")},
                *([{"name": "redhat:catalog-source-name", "value": source_name}] if source_name else []),
                *([{"name": "redhat:catalog-source-nvr", "value": source_nvr}] if source_nvr else []),
            ],
        })
    document = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "Red Hat", "name": "cve-report", "version": "1.0"}],
            "component": {"type": "container", "name": subject.repository, "version": subject.digest,
                          "purl": f"pkg:oci/{subject.repository}@{subject.digest}"},
            "properties": [
                {"name": "redhat:catalog-image", "value": subject.resolved_reference},
                {"name": "redhat:catalog-rpm-manifest", "value": subject.rpm_manifest_url},
                {"name": "redhat:catalog-retrieved-at", "value": timestamp},
            ],
        },
        "components": components,
    }
    Path(path).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return document


def _component_match(finding, rpm):
    if finding.component_name != rpm.get("name"):
        return False
    if not finding.component_version:
        return True
    nvr = _rpm_nvr(rpm)
    epoch = str(rpm.get("epoch", "") or "")
    version_release = f"{rpm.get('version', '')}-{rpm.get('release', '')}"
    candidates = {rpm.get("version", ""), version_release, nvr, rpm.get("nvra", "")}
    if epoch and epoch not in {"0", "(none)"}:
        candidates.add(f"{epoch}:{version_release}")
    return finding.component_version in candidates


def podman_status(runner=subprocess.run):
    """Return whether the local Podman service can be used for validation."""
    try:
        completed = runner(
            ["podman", "info", "--format", "json"],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except FileNotFoundError:
        return {"available": False, "state": "unavailable", "message": "Podman is not installed."}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": False, "state": "unavailable", "message": f"Podman is unavailable: {exc}"}
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "").strip() or "Podman is not running."
        return {"available": False, "state": "unavailable", "message": f"Podman is unavailable: {detail}"}
    return {"available": True, "state": "available", "message": "Podman is available for local image validation."}


def _podman_references(subject):
    """Use registry.redhat.io first for repositories requiring authentication."""
    registries = [subject.registry]
    if subject.registry == CATALOG_REGISTRY:
        registries.insert(0, AUTHENTICATED_REGISTRY)
    return list(dict.fromkeys(
        f"{registry}/{subject.repository}@{subject.digest}" for registry in registries
    ))


def _parse_podman_rpms(output):
    rpms = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            continue
        name, epoch, version, release, architecture = fields
        if not name or not version or not release:
            continue
        rpms.append({
            "name": name, "epoch": epoch, "version": version, "release": release,
            "architecture": architecture,
            "nvra": f"{name}-{version}-{release}.{architecture}",
        })
    return rpms


def inspect_image_with_podman(subject, runner=subprocess.run, availability=None):
    """Pull and query the exact image's RPM database via local Podman.

    Catalog data remains the SBOM/provenance source.  This is independent local
    evidence that the binary RPM is installed in the image the user confirmed.
    """
    availability = availability or podman_status(runner)
    if not availability.get("available"):
        return {**availability, "rpms": []}
    pull_errors = []
    reference = None
    for candidate in _podman_references(subject):
        try:
            completed = runner(
                ["podman", "pull", "--arch", subject.architecture, candidate],
                capture_output=True, text=True, check=False, timeout=PODMAN_TIMEOUT_SECONDS,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            pull_errors.append(str(exc))
            continue
        if completed.returncode == 0:
            reference = candidate
            break
        pull_errors.append((completed.stderr or completed.stdout or "pull failed").strip())
    if not reference:
        detail = " ".join(error for error in pull_errors if error).replace("\n", " ")[:500]
        return {
            "available": True, "state": "image-unavailable", "message": f"Podman could not pull the confirmed image. {detail}",
            "rpms": [],
        }
    try:
        completed = runner(
            ["podman", "run", "--rm", "--platform", f"linux/{subject.architecture}",
             "--entrypoint", "/usr/bin/rpm", reference, "-qa", "--qf",
             "%{NAME}\\t%{EPOCHNUM}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n"],
            capture_output=True, text=True, check=False, timeout=PODMAN_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"available": True, "state": "rpm-query-failed", "message": f"Podman RPM query failed: {exc}", "rpms": []}
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "RPM query failed").strip().replace("\n", " ")[:500]
        return {"available": True, "state": "rpm-query-failed", "message": f"Podman RPM query failed: {detail}", "rpms": []}
    rpms = _parse_podman_rpms(completed.stdout)
    if not rpms:
        return {"available": True, "state": "rpm-query-failed", "message": "Podman returned no installed RPMs.", "rpms": []}
    return {
        "available": True, "state": "verified", "message": f"Validated {len(rpms)} installed RPMs from the local image.",
        "reference": reference, "rpms": rpms,
    }


def _grype_match_rationale(finding):
    """Explain a Grype decision from its emitted matcher evidence.

    The default table format does not expose Grype's matcher, namespace, or
    version constraint.  JSON does; preserve those fields and apply the
    versioned rule database rather than guessing at the scanner's internals.
    """
    rules = SCANNER_RATIONALE_RULES["grype"]
    details = finding.raw.get("Grype match details", [])
    if not isinstance(details, list) or not details:
        table_rule = rules["human_table"]
        return {
            "kind": "scanner-table",
            "summary": table_rule["summary"],
            "limitation": table_rule["limitation"],
            "evidence": [],
        }
    evidence = []
    summaries = []
    limitations = []
    for detail in details:
        if not isinstance(detail, dict):
            continue
        match_type = detail.get("type", "default")
        rule = rules["match_types"].get(match_type, rules["match_types"]["default"])
        matcher = detail.get("matcher", "unknown matcher")
        searched = detail.get("searchedBy", {}) if isinstance(detail.get("searchedBy"), dict) else {}
        found = detail.get("found", {}) if isinstance(detail.get("found"), dict) else {}
        namespace = searched.get("namespace") or finding.raw.get("Grype namespace", "")
        constraint = found.get("versionConstraint", "")
        summaries.append(f"{rule['summary']} ({match_type} via {matcher})")
        limitations.append(rule["limitation"])
        evidence.append({
            "type": match_type,
            "matcher": matcher,
            "namespace": namespace,
            "versionConstraint": constraint,
            "searchedBy": searched,
            "found": found,
        })
    if not evidence:
        return {
            "kind": "scanner-table",
            "summary": rules["human_table"]["summary"],
            "limitation": rules["human_table"]["limitation"],
            "evidence": [],
        }
    return {
        "kind": "grype-match-details",
        "summary": " ".join(dict.fromkeys(summaries)),
        "limitation": " ".join(dict.fromkeys(limitations)),
        "evidence": evidence,
    }


def scanner_match_rationale(finding):
    """Return an auditable explanation of a scanner's package/CVE assertion."""
    if finding.scanner_name == "grype":
        return _grype_match_rationale(finding)
    return {
        "kind": "scanner-row",
        "summary": f"{finding.scanner_name} reported this package/CVE pair.",
        "limitation": "The supplied scanner format does not include vendor matcher evidence.",
        "evidence": [],
    }


def _rpm_evidence(rpms):
    return [
        {"name": rpm.get("name"), "nvra": rpm.get("nvra"), "architecture": rpm.get("architecture")}
        for rpm in rpms
    ]


def finding_evidence(findings, subject, rpms, podman_validation=None):
    """Create per-finding provenance records without claiming source/file origin."""
    evidence = []
    local_rpms = (podman_validation or {}).get("rpms", [])
    podman_verified = (podman_validation or {}).get("state") == "verified"
    for finding in findings:
        rationale = scanner_match_rationale(finding)
        matches = [rpm for rpm in rpms if _component_match(finding, rpm)]
        same_name = [rpm for rpm in rpms if finding.component_name == rpm.get("name")]
        local_matches = [rpm for rpm in local_rpms if _component_match(finding, rpm)]
        local_same_name = [rpm for rpm in local_rpms if finding.component_name == rpm.get("name")]
        if matches:
            image_membership = "exact RPM name/version match in Red Hat Catalog manifest"
            confidence = "unresolved"
            origin_kind = "unknown"
            limitation = "Catalog inventory proves image membership only; source, parent/builder, and file origin require BOMQ or layer evidence."
        elif same_name:
            image_membership = "component name found, but scanner version does not match catalog manifest"
            confidence = "conflicting"
            origin_kind = "conflicting"
            limitation = "Do not apply a component-specific conclusion until the scanner/image version mismatch is resolved."
        else:
            image_membership = "component was not found in the resolved image RPM manifest"
            confidence = "unresolved"
            origin_kind = "unknown"
            limitation = "The scanner component may be non-RPM, application content, or associated with a different image."
        if podman_verified:
            if local_matches:
                image_membership = "exact RPM name/version match in the local image RPM database"
                confidence = "confirmed"
                origin_kind = "unknown"
                limitation = "Local Podman evidence validates RPM presence; source, parent/builder, and file origin still require BOMQ or layer evidence."
            elif local_same_name:
                image_membership = "component name found in the local image RPM database, but scanner version does not match"
                confidence = "conflicting"
                origin_kind = "conflicting"
                limitation = "Do not apply a component-specific conclusion until the scanner/image version mismatch is resolved."
            else:
                image_membership = "component was not found in the local image RPM database"
                confidence = "unresolved"
                origin_kind = "unknown"
                limitation = "The scanner component may be non-RPM application content; local RPM validation alone cannot establish a false positive."
        evidence.append({
            "cve_id": finding.cve_id,
            "scanner": {
                "component": finding.component_name, "version": finding.component_version,
                "origin": finding.component_origin, "match_type": finding.scanner_match_type,
                "remediation_status": finding.scanner_status, "severity": finding.scanner_severity,
                "name": finding.scanner_name,
                "raw": finding.raw,
            },
            "scanner_match_rationale": rationale,
            "image": subject.evidence(),
            "matched_catalog_rpms": _rpm_evidence(matches or same_name),
            "matched_podman_rpms": _rpm_evidence(local_matches or local_same_name),
            "image_membership": image_membership,
            "origin_kind": origin_kind,
            "origin_image_digest": None,
            "first_introducer_digest": None,
            "evidence_type": ["contextual_sbom", *(["podman_rpm_database"] if podman_verified else [])],
            "evidence_confidence": confidence,
            "limitation": limitation,
            "podman": {key: value for key, value in (podman_validation or {}).items() if key != "rpms"},
        })
    return evidence


def write_scanner_evidence(path, findings, subject, rpms, podman_validation=None):
    records = finding_evidence(findings, subject, rpms, podman_validation)
    payload = {
        "schema": "cve-report.scanner-evidence/v1",
        "evaluated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "subject": subject.evidence(),
        "finding_count": len(records),
        "findings": records,
        "podman": {key: value for key, value in (podman_validation or {}).items() if key != "rpms"},
    }
    serialized = json.dumps(payload, indent=2) + "\n"
    Path(path).write_text(serialized, encoding="utf-8")
    payload["sha256"] = hashlib.sha256(serialized.encode()).hexdigest()
    return payload


def reconcile_scanner_results(results_path, evidence_payload):
    """Limit scanner results to reported CVEs and retain unverified findings.

    Scanner evidence remains in its dedicated artifact.  Analysis results
    contain only the normal finding schema, without scanner-specific detail.
    """
    path = Path(results_path)
    results = json.loads(path.read_text(encoding="utf-8"))
    records_by_cve = {}
    for record in evidence_payload.get("findings", []):
        scanner = record.get("scanner", {})
        cve_id = record.get("cve_id", "")
        if not cve_id or not scanner:
            continue
        records_by_cve.setdefault(cve_id, []).append(record)

    scanner_cves = set(records_by_cve)
    findings = [
        finding for finding in results.get("findings", [])
        if finding.get("cveId", "") in scanner_cves
    ]
    for finding in findings:
        finding.pop("scannerRationale", None)
    existing_cves = {finding.get("cveId", "") for finding in findings}
    for cve_id in sorted(scanner_cves - existing_cves):
        records = records_by_cve[cve_id]
        first = records[0]
        scanner = first["scanner"]
        severity = (scanner.get("severity") or "").upper()
        impact = {
            "CRITICAL": "CRITICAL", "HIGH": "IMPORTANT", "MEDIUM": "MODERATE", "LOW": "LOW",
        }.get(severity, "UNSET")
        findings.append({
            "cveId": cve_id,
            "impact": impact,
            "cvss": None,
            "status": [],
            "remediationStatus": "unverified",
            "advisories": [],
            "title": "",
            "components": [{
                "originComponent": scanner.get("component", "unknown"),
                "originNvrs": [
                    "-".join(part for part in (scanner.get("component", ""), scanner.get("version", "")) if part)
                ],
                "imageComponents": [item.get("nvra", "") for item in first.get("matched_catalog_rpms", [])],
                "upstreamStreams": [],
                "remediationStatus": "unverified",
                "advisories": [],
            }],
        })
    findings.sort(key=lambda item: item["cveId"])
    results["findings"] = findings
    summary = results.setdefault("summary", {})
    summary["scannerReportedCves"] = len(scanner_cves)
    summary["unfixedCves"] = sum(item.get("remediationStatus") == "unfixed" for item in findings)
    summary["fixedCves"] = sum(item.get("remediationStatus") == "fixed" for item in findings)
    summary["unverifiedCves"] = sum(item.get("remediationStatus") == "unverified" for item in findings)
    summary["unresolvedCves"] = summary["unfixedCves"]
    path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results


def write_scanner_review_csv(path, results_path, evidence_payload):
    """Export the scanner-review result table as a conventional CSV file.

    This preserves the table's one-row-per-CVE model while retaining the
    scanner assertion and component provenance in spreadsheet-friendly columns.
    Scanner-specific values come from the evidence artifact, keeping them out
    of the structured analysis results.
    """
    results = json.loads(Path(results_path).read_text(encoding="utf-8"))
    evidence_by_cve = {}
    for record in evidence_payload.get("findings", []):
        cve_id = record.get("cve_id", "")
        if cve_id:
            evidence_by_cve.setdefault(cve_id, []).append(record)

    def values(items, key):
        flattened = []
        for item in items or []:
            raw_values = item.get(key, [])
            if isinstance(raw_values, (str, int, float)):
                raw_values = [raw_values]
            flattened.extend(str(value) for value in raw_values if value)
        return "; ".join(dict.fromkeys(flattened))

    def scanner_values(records, key):
        return "; ".join(dict.fromkeys(
            str(record.get("scanner", {}).get(key, ""))
            for record in records if record.get("scanner", {}).get(key)
        ))

    def evidence_values(records, key):
        flattened = []
        for record in records:
            raw_values = record.get(key, [])
            if isinstance(raw_values, (str, int, float)):
                raw_values = [raw_values]
            if isinstance(raw_values, list) and raw_values and isinstance(raw_values[0], dict):
                raw_values = [item.get("nvra", "") for item in raw_values]
            flattened.extend(str(value) for value in raw_values if value)
        return "; ".join(dict.fromkeys(flattened))

    fieldnames = [
        "CVE", "CVE URL", "Impact", "CVSS", "Status", "Advisories", "Advisory URLs",
        "Origin component", "Origin component NVR", "BOMQ upstream stream(s)",
        "Scanner", "Scanner component", "Scanner version", "Scanner match type",
        "Scanner status", "Scanner severity", "Image membership",
        "Matched Catalog RPMs", "Matched local image RPMs", "Limitations",
    ]
    with Path(path).open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for finding in results.get("findings", []):
            cve_id = finding.get("cveId", "")
            advisories = finding.get("advisories", [])
            evidence_records = evidence_by_cve.get(cve_id, [])
            writer.writerow({
                "CVE": cve_id,
                "CVE URL": f"https://access.redhat.com/security/cve/{cve_id}" if cve_id else "",
                "Impact": finding.get("impact", ""),
                "CVSS": finding.get("cvss", ""),
                "Status": finding.get("remediationStatus", ""),
                "Advisories": "; ".join(advisories),
                "Advisory URLs": "; ".join(
                    f"https://access.redhat.com/errata/{advisory}" for advisory in advisories
                ),
                "Origin component": values(finding.get("components"), "originComponent"),
                "Origin component NVR": values(finding.get("components"), "originNvrs"),
                "BOMQ upstream stream(s)": values(finding.get("components"), "upstreamStreams"),
                "Scanner": scanner_values(evidence_records, "name"),
                "Scanner component": scanner_values(evidence_records, "component"),
                "Scanner version": scanner_values(evidence_records, "version"),
                "Scanner match type": scanner_values(evidence_records, "match_type"),
                "Scanner status": scanner_values(evidence_records, "remediation_status"),
                "Scanner severity": scanner_values(evidence_records, "severity"),
                "Image membership": evidence_values(evidence_records, "image_membership"),
                "Matched Catalog RPMs": evidence_values(evidence_records, "matched_catalog_rpms"),
                "Matched local image RPMs": evidence_values(evidence_records, "matched_podman_rpms"),
                "Limitations": evidence_values(evidence_records, "limitation"),
            })


def render_scanner_evidence_markdown(payload):
    subject = payload["subject"]
    lines = [
        "# Scanner finding provenance", "",
        "This is local analysis derived from the vulnerability report and Red Hat Catalog inventory; it is not vendor-issued VEX.", "",
        f"**Scanned image:** `{subject['requested_reference']}`",  
        f"**Resolved image:** `{subject['resolved_reference']}`",  
        f"**Platform:** `{subject['architecture']}`",  
        f"**Catalog RPM manifest:** {subject['rpm_manifest_url']}", "",
        "## Finding evidence", "",
        "| CVE | Scanner/component | Image RPM evidence | Origin confidence | Limitation |",
        "|-----|-------------------|--------------------|-------------------|------------|",
    ]
    for record in payload["findings"]:
        scanner = record["scanner"]
        matches = ", ".join(item["nvra"] for item in record.get("matched_podman_rpms", []) or record["matched_catalog_rpms"]) or "not found"
        component = f"{scanner['name']}: {scanner['component']} {scanner['version']}".strip()
        lines.append("| {cve} | {component} | {membership}: {matches} | {kind}/{confidence} | {limitation} |".format(
            cve=record["cve_id"], component=component,
            membership=record["image_membership"], matches=matches,
            kind=record["origin_kind"], confidence=record["evidence_confidence"],
            limitation=record["limitation"],
        ))
    lines.extend(["", "Scanner raw rows and immutable image identifiers are retained in `scanner-evidence.json`.", ""])
    return "\n".join(lines)


def prepare_scanner_analysis(report_path, image_reference, architecture, sbom_path, evidence_path, image_validator=None):
    """Create analysis artifacts for a supported vulnerability report.

    Returns the resolved subject and local catalog-derived SBOM path for the
    existing CVE/VEX analysis path.
    """
    findings = parse_vulnerability_report(report_path)
    reference = choose_image_reference(findings, image_reference)
    subject = resolve_redhat_image(reference, architecture)
    rpms = fetch_rpm_manifest(subject)
    write_catalog_sbom(sbom_path, subject, rpms)
    podman_validation = image_validator(subject) if image_validator else None
    evidence = write_scanner_evidence(evidence_path, findings, subject, rpms, podman_validation)
    return subject, evidence
