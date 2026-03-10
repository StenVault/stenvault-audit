"""
Layer 5: Composite confidence scoring.
Computes a final confidence score for each finding based on multiple signals.
"""


# Weight configuration for composite score
WEIGHTS = {
    "consensus": 0.30,       # Cross-validation agreement
    "evidence": 0.25,        # AST evidence quality
    "semgrep": 0.20,         # Semgrep corroboration
    "design_doc": 0.15,      # Design doc distance (inversely correlated)
    "model_diversity": 0.10, # Multi-model agreement
}

# Adversarial findings get a penalty unless corroborated
ADVERSARIAL_PENALTY = -0.15


def compute_confidence(finding: dict) -> float:
    """
    Compute composite confidence score for a single finding.

    Score components:
    - consensus (0.30): From cross-validation runs_agreed/total_runs
    - evidence (0.25): AST evidence quality (exact=1.0, fuzzy=0.6, no_match=0.1)
    - semgrep (0.20): Semgrep corroboration (yes=1.0, no=0.3, N/A=0.5)
    - design_doc (0.15): Inverse of design doc distance (further = more likely real)
    - model_diversity (0.10): Multi-model vs single-model consensus
    """
    score = 0.0

    # 1. Consensus score
    consensus = finding.get("consensus", 0.5)
    score += WEIGHTS["consensus"] * consensus

    # 2. Evidence quality score
    evidence_quality = finding.get("evidence_quality", "fuzzy")
    evidence_scores = {
        "exact": 1.0,
        "fuzzy": 0.6,
        "no_match": 0.1,
    }
    score += WEIGHTS["evidence"] * evidence_scores.get(evidence_quality, 0.5)

    # 3. Semgrep corroboration
    semgrep_corroborated = finding.get("semgrep_corroborated")
    if semgrep_corroborated is True:
        score += WEIGHTS["semgrep"] * 1.0
    elif semgrep_corroborated is False:
        score += WEIGHTS["semgrep"] * 0.3
    else:
        # No Semgrep data available — neutral
        score += WEIGHTS["semgrep"] * 0.5

    # 4. Design doc distance (higher distance = less likely to be a known design decision)
    design_distance = finding.get("design_doc_distance", 0.5)
    # Normalize: distance > 0.5 is good (not a design decision), < 0.35 is bad
    if design_distance >= 0.5:
        doc_score = 1.0
    elif design_distance >= 0.35:
        doc_score = 0.6
    else:
        doc_score = 0.2
    score += WEIGHTS["design_doc"] * doc_score

    # 5. Model diversity
    consensus_type = finding.get("consensus_type", "cross-temperature")
    if consensus_type == "cross-model":
        # Multi-model agreement is stronger signal
        models_agreed = finding.get("models_agreed", [])
        if len(set(models_agreed)) > 1:
            score += WEIGHTS["model_diversity"] * 1.0
        else:
            score += WEIGHTS["model_diversity"] * 0.7
    else:
        score += WEIGHTS["model_diversity"] * 0.5

    # Apply adversarial penalty if not corroborated
    finding_type = finding.get("finding_type", "checklist")
    if finding_type == "adversarial":
        if not finding.get("semgrep_corroborated") and finding.get("evidence_quality") != "exact":
            score += ADVERSARIAL_PENALTY

    # Apply boosts/penalties from earlier layers
    score += finding.get("confidence_boost", 0)
    score -= finding.get("confidence_penalty", 0)

    # Clamp to [0, 1]
    return max(0.0, min(1.0, round(score, 3)))


def apply_confidence_scores(findings: list[dict]) -> list[dict]:
    """
    Compute and apply confidence scores to all findings.
    Also assigns a confidence_tier: "high" (>= 0.7), "medium" (>= 0.4), "low" (< 0.4).
    """
    for f in findings:
        status = f.get("triage_status", "")
        if status in ("rejected", "rejected_by_ml", "whitelisted"):
            f["confidence_score"] = 0.0
            f["confidence_tier"] = "rejected"
            continue

        score = compute_confidence(f)
        f["confidence_score"] = score

        if score >= 0.7:
            f["confidence_tier"] = "high"
        elif score >= 0.4:
            f["confidence_tier"] = "medium"
        else:
            f["confidence_tier"] = "low"

    return findings
