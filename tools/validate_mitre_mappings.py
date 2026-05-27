from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


TECHNIQUE_RE = re.compile(r"\[(T\d{4}(?:\.\d{3})?)\]\(https://attack\.mitre\.org/techniques/[^)]+\)")
DETECTION_RE = re.compile(r"\[(DET\d{4})\]\(https://attack\.mitre\.org/detectionstrategies/[^)]+\)")
SKIP_FILES = {"_TEMPLATE.md"}
ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


@dataclass(frozen=True)
class PairReference:
    file_path: Path
    line_number: int
    technique_id: str
    detection_id: str


@dataclass(frozen=True)
class NoStrategyClaim:
    file_path: Path
    line_number: int
    technique_id: str


@dataclass
class StixBundle:
    technique_to_detect_ids: Dict[str, Set[str]]
    detect_to_technique_ids: Dict[str, Set[str]]


def fetch_html(url: str) -> str:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (compatible; mitre-mapping-validator/1.0)"
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8", errors="replace")


def load_stix_bundle() -> StixBundle:
    data = json.loads(fetch_html(ATTACK_STIX_URL))
    objects = data["objects"]

    technique_object_to_external: Dict[str, str] = {}
    detection_object_to_external: Dict[str, str] = {}
    revoked_by: Dict[str, str] = {}

    for obj in objects:
        external_refs = obj.get("external_references", [])
        external_id = next((ref.get("external_id") for ref in external_refs if ref.get("external_id")), None)
        if obj.get("type") == "attack-pattern" and external_id and external_id.startswith("T"):
            technique_object_to_external[obj["id"]] = external_id
        if obj.get("type") == "x-mitre-detection-strategy" and external_id and external_id.startswith("DET"):
            detection_object_to_external[obj["id"]] = external_id

    for obj in objects:
        if obj.get("type") != "relationship":
            continue
        if obj.get("relationship_type") == "revoked-by":
            revoked_by[obj["source_ref"]] = obj["target_ref"]

    def resolve_technique_object_id(object_id: str) -> str:
        seen: Set[str] = set()
        current = object_id
        while current in revoked_by and current not in seen:
            seen.add(current)
            current = revoked_by[current]
        return current

    technique_to_detect_ids: Dict[str, Set[str]] = {}
    detect_to_technique_ids: Dict[str, Set[str]] = {}

    for obj in objects:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "detects":
            continue
        source_ref = obj.get("source_ref")
        target_ref = obj.get("target_ref")
        detect_id = detection_object_to_external.get(source_ref)
        if not detect_id or target_ref not in technique_object_to_external:
            continue
        resolved_target = resolve_technique_object_id(target_ref)
        technique_id = technique_object_to_external.get(resolved_target)
        if not technique_id:
            continue

        technique_to_detect_ids.setdefault(technique_id, set()).add(detect_id)
        detect_to_technique_ids.setdefault(detect_id, set()).add(technique_id)

    return StixBundle(
        technique_to_detect_ids=technique_to_detect_ids,
        detect_to_technique_ids=detect_to_technique_ids,
    )


def iter_connector_files(connectors_dir: Path) -> Iterable[Path]:
    for file_path in sorted(connectors_dir.glob("*.md")):
        if file_path.name.startswith("."):
            continue
        if file_path.name in SKIP_FILES:
            continue
        yield file_path


def parse_connector_file(file_path: Path) -> Tuple[List[PairReference], List[NoStrategyClaim]]:
    lines = file_path.read_text(encoding="utf-8").splitlines()
    pair_refs: List[PairReference] = []
    no_strategy_claims: List[NoStrategyClaim] = []

    for line_number, line in enumerate(lines, start=1):
        technique_ids = TECHNIQUE_RE.findall(line)
        detection_ids = DETECTION_RE.findall(line)
        if not technique_ids:
            continue

        if detection_ids:
            if len(technique_ids) == 1 and len(detection_ids) == 1:
                pair_refs.append(
                    PairReference(
                        file_path=file_path,
                        line_number=line_number,
                        technique_id=technique_ids[0],
                        detection_id=detection_ids[0],
                    )
                )
            continue

        if "No MITRE Detection Strategy published" in line or "no published strategy" in line:
            if len(technique_ids) == 1:
                no_strategy_claims.append(
                    NoStrategyClaim(
                        file_path=file_path,
                        line_number=line_number,
                        technique_id=technique_ids[0],
                    )
                )

    return pair_refs, no_strategy_claims


def validate_pairs(
    pair_refs: List[PairReference],
    stix_bundle: StixBundle,
) -> List[str]:
    findings: List[str] = []

    for pair in pair_refs:
        in_stix_relationships = pair.detection_id in stix_bundle.technique_to_detect_ids.get(pair.technique_id, set())
        if in_stix_relationships:
            continue

        findings.append(
            (
                f"PAIR_MISMATCH {pair.file_path}:{pair.line_number} "
                f"{pair.technique_id} -> {pair.detection_id} "
                f"(stix has: {sorted(stix_bundle.technique_to_detect_ids.get(pair.technique_id, set())) or ['none']})"
            )
        )

    return findings


def validate_no_strategy_claims(
    claims: List[NoStrategyClaim],
    stix_bundle: StixBundle,
) -> List[str]:
    findings: List[str] = []

    for claim in claims:
        detection_ids = stix_bundle.technique_to_detect_ids.get(claim.technique_id, set())
        if detection_ids:
            findings.append(
                (
                    f"STALE_NO_STRATEGY {claim.file_path}:{claim.line_number} "
                    f"{claim.technique_id} has published detections: "
                    f"{', '.join(sorted(detection_ids))}"
                )
            )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate MITRE technique/detection mappings in connector markdown.")
    parser.add_argument(
        "--connectors-dir",
        default=str(Path(__file__).resolve().parents[1] / "connectors"),
        help="Path to the connectors directory.",
    )
    args = parser.parse_args()

    connectors_dir = Path(args.connectors_dir)
    if not connectors_dir.exists():
        print(f"Connectors directory not found: {connectors_dir}", file=sys.stderr)
        return 2

    pair_refs: List[PairReference] = []
    no_strategy_claims: List[NoStrategyClaim] = []
    for file_path in iter_connector_files(connectors_dir):
        pairs, claims = parse_connector_file(file_path)
        pair_refs.extend(pairs)
        no_strategy_claims.extend(claims)

    stix_bundle = load_stix_bundle()
    try:
        findings = validate_pairs(pair_refs, stix_bundle)
        findings.extend(validate_no_strategy_claims(no_strategy_claims, stix_bundle))
    except urllib.error.URLError as exc:
        print(f"MITRE fetch failed: {exc}", file=sys.stderr)
        return 2

    print(
        f"Validated {len(pair_refs)} technique/detection pairs and {len(no_strategy_claims)} no-strategy claims "
        f"across {len(list(iter_connector_files(connectors_dir)))} connector pages."
    )
    if findings:
        for finding in findings:
            print(finding)
        return 1

    print("No mismatches found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())