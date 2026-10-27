"""Versioned OriginScope assessment profiles and policy verdicts.

Profiles are intentionally plain JSON so that policy is reviewable alongside
the application.  An assessment bundle stores a fully expanded copy of the
selected profile, so later edits do not change a completed run's verdict.
"""

import copy
import json
from datetime import date
from pathlib import Path


PROFILE_SCHEMA = "originscope-assessment-profiles/v1"
DEFAULT_PROFILE_ID = "report-only-v1"
PROFILE_PATH = Path(__file__).with_name("assessment_profiles.json")


def _load_catalog(path=PROFILE_PATH):
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Unable to load assessment profiles: {exc}") from exc
    if document.get("schema") != PROFILE_SCHEMA or not isinstance(document.get("profiles"), list):
        raise RuntimeError("Assessment profiles have an unsupported format.")
    profiles = {}
    for profile in document["profiles"]:
        profile_id = profile.get("id") if isinstance(profile, dict) else None
        if not profile_id or not isinstance(profile.get("version"), str) or profile_id in profiles:
            raise RuntimeError("Assessment profiles contain an invalid or duplicate profile.")
        profiles[profile_id] = profile
    if DEFAULT_PROFILE_ID not in profiles:
        raise RuntimeError(f"Assessment profiles must include {DEFAULT_PROFILE_ID}.")
    return profiles


def profile(profile_id=DEFAULT_PROFILE_ID):
    """Return a defensive copy of one versioned profile definition."""
    profiles = _load_catalog()
    if not isinstance(profile_id, str):
        raise ValueError("Choose a supported assessment profile.")
    try:
        return copy.deepcopy(profiles[profile_id or DEFAULT_PROFILE_ID])
    except KeyError as exc:
        raise ValueError("Choose a supported assessment profile.") from exc


def profile_options():
    """Return UI-safe descriptions of the available built-in profiles."""
    return [
        {key: item[key] for key in ("id", "version", "name", "description")}
        for item in _load_catalog().values()
    ]


def _active_finding(finding):
    remediation = finding.get("remediationStatus")
    if remediation:
        return remediation == "unfixed"
    return bool({"known_affected", "under_investigation", "first_affected"} & set(finding.get("status", [])))


def _current_waivers(profile_definition, rule_id):
    current = {}
    today = date.today()
    for waiver in profile_definition.get("waivers", []):
        if waiver.get("ruleId") not in (None, rule_id):
            continue
        cve_id = waiver.get("cveId")
        if not cve_id or not waiver.get("reason"):
            continue
        try:
            expires = date.fromisoformat(waiver.get("expires", ""))
        except ValueError:
            continue
        if expires >= today:
            current[cve_id] = {
                "cveId": cve_id,
                "reason": waiver["reason"],
                "expires": expires.isoformat(),
            }
    return current


def _rule_result(rule, findings, result_available):
    rule_id = rule.get("id", "unnamed-rule")
    result = {
        "id": rule_id,
        "description": rule.get("description", ""),
        "type": rule.get("type"),
        "enforcement": rule.get("enforcement", "informational"),
        "status": "unknown",
    }
    if rule["type"] == "analysis-complete":
        result["status"] = "pass" if result_available else "fail"
        return result
    if not result_available:
        result["reason"] = "Structured analysis results are unavailable."
        return result

    active = [item for item in findings if _active_finding(item)]
    if rule["type"] == "active-cve-count":
        impact = rule.get("impact")
        matched = [item for item in active if not impact or item.get("impact") == impact]
        result.update({
            "count": len(matched),
            "cveIds": sorted(item.get("cveId") for item in matched if item.get("cveId")),
        })
        maximum = rule.get("maximum")
        if maximum is None:
            result["status"] = "pass"
            return result
        result["maximum"] = maximum
        result["status"] = "pass" if len(matched) <= maximum else "fail"
        return result
    if rule["type"] == "origin-evidence":
        if not active:
            result["status"] = "not_applicable"
            return result
        without_evidence = []
        for finding in active:
            components = finding.get("components", [])
            if not components or not any(component.get("originNvrs") for component in components):
                without_evidence.append(finding.get("cveId"))
        result["missingEvidenceCveIds"] = sorted(cve_id for cve_id in without_evidence if cve_id)
        result["status"] = "pass" if not without_evidence else "unknown"
        return result

    result["reason"] = f"Unsupported rule type: {rule['type']}"
    return result


def evaluate(profile_definition, results_document):
    """Evaluate a profile and return immutable, explainable policy evidence."""
    result_available = isinstance(results_document, dict) and isinstance(results_document.get("summary"), dict)
    findings = results_document.get("findings", []) if result_available else []
    if not isinstance(findings, list):
        findings = []
        result_available = False
    rules = []
    for rule in profile_definition.get("rules", []):
        evaluated = _rule_result(rule, findings, result_available)
        if evaluated["status"] == "fail" and rule.get("type") == "active-cve-count":
            waivers = _current_waivers(profile_definition, evaluated["id"])
            failing_ids = evaluated["cveIds"]
            waived = [waivers[cve_id] for cve_id in failing_ids if cve_id in waivers]
            unwaived = [cve_id for cve_id in failing_ids if cve_id not in waivers]
            evaluated["waivers"] = waived
            evaluated["unwaivedCveIds"] = unwaived
            if not unwaived:
                evaluated["status"] = "waived"
        rules.append(evaluated)

    blocking = [item for item in rules if item["enforcement"] == "blocking"]
    if any(item["status"] == "fail" for item in blocking):
        verdict = "fail"
    elif any(item["status"] == "unknown" for item in blocking):
        verdict = "unknown"
    else:
        verdict = "pass"
    return {
        "schema": "originscope-policy-verdict/v1",
        "profile": {
            key: profile_definition[key]
            for key in ("id", "version", "name", "description")
        },
        "verdict": verdict,
        "rules": rules,
    }
