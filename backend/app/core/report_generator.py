"""Report generation for CodeShield AI.

Combines the security and architecture results into a weighted overall
score, a letter grade, a human-readable summary and a prioritized,
data-driven list of recommendations.

Pure logic: no network access, no side effects.
"""

from ..utils.helpers import calculate_grade

_SECURITY_WEIGHT = 0.55
_ARCH_WEIGHT = 0.45
_MAX_RECOMMENDATIONS = 8


def _as_float(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _build_summary(
    overall: float,
    grade: str,
    security: dict,
    architecture: dict,
    repo_info: dict,
    meta: dict,
) -> str:
    """Compose a 2-3 sentence human-readable summary of the analysis."""
    name = repo_info.get("full_name") or (
        f"{meta.get('owner', '?')}/{meta.get('repo', '?')}".strip("/")
    )
    counts = security.get("summary", {}) or {}
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    total = counts.get("total", 0)
    sec_score = security.get("score", 0)
    arch_score = architecture.get("score", 0)

    sentence1 = (
        f"CodeShield AI analyzed {name}: overall score {overall}/100 "
        f"(grade {grade}) — security {sec_score}/100, architecture {arch_score}/100."
    )

    if total == 0:
        sentence2 = "No security findings were detected in the scanned files."
    else:
        parts = []
        if critical:
            parts.append(f"{critical} critical")
        if high:
            parts.append(f"{high} high-severity")
        severity_text = " and ".join(parts) if parts else f"{total} lower-severity"
        sentence2 = f"The scan surfaced {total} finding(s), including {severity_text}."

    practices = architecture.get("best_practices", []) or []
    passed = [p["check"] for p in practices if p.get("passed")]
    missing = [p["check"] for p in practices if not p.get("passed")]
    if missing:
        strongest = ", ".join(passed[:3]) if passed else "none yet"
        sentence3 = f"Strongest areas: {strongest}; biggest gaps: {', '.join(missing[:3])}."
    else:
        sentence3 = "All 7 architecture best-practice checks passed."

    return " ".join([sentence1, sentence2, sentence3])


def _build_recommendations(security: dict, architecture: dict) -> list[str]:
    """Generate up to 8 actionable recommendations from actual findings."""
    recommendations: list[str] = []
    findings = security.get("findings", []) or []

    def _push(text: str) -> None:
        if len(recommendations) < _MAX_RECOMMENDATIONS and text not in recommendations:
            recommendations.append(text)

    # 1) Critical findings first — each names the exact location.
    for finding in findings:
        if finding.get("severity") == "critical":
            location = finding.get("file") or "repository"
            line = finding.get("line") or 0
            _push(
                f"URGENT — {finding.get('title')} at {location}:{line}. "
                "Revoke/rotate the exposed credential immediately and move it "
                "to environment variables or a secrets manager."
            )

    # 2) High-severity findings, most severe first (findings are pre-sorted).
    for finding in findings:
        if finding.get("severity") == "high":
            location = finding.get("file") or "repository"
            line = finding.get("line") or 0
            detail = finding.get("description") or ""
            _push(f"Fix HIGH severity: {finding.get('title')} at {location}:{line} — {detail}".strip(" —"))

    # 3) Missing best-practice items, largest bonus first.
    practices = architecture.get("best_practices", []) or []
    for practice in sorted(practices, key=lambda p: p.get("bonus", 0), reverse=True):
        if not practice.get("passed"):
            _push(
                f"Missing {practice.get('check')} — adding it earns "
                f"+{practice.get('bonus', 0)} architecture points."
            )

    # 4) General guidance when the security posture is weak.
    if _as_float(security.get("score")) < 70:
        _push(
            "Security score is below 70 — address high-severity findings "
            "before the next release."
        )

    return recommendations[:_MAX_RECOMMENDATIONS]


def generate(security: dict, architecture: dict, repo_info: dict, meta: dict) -> dict:
    """Build the final report from scanner and analyzer output.

    Args:
        security: result of ``security_scanner.scan()``.
        architecture: result of ``architecture_analyzer.analyze()``.
        repo_info: GitHub repository metadata dict.
        meta: job metadata (owner, repo, branch, files_analyzed, ...).

    Returns:
        dict with ``overall_score``, ``grade``, ``summary`` and
        ``recommendations``.
    """
    security = security or {}
    architecture = architecture or {}
    repo_info = repo_info or {}
    meta = meta or {}

    overall = round(
        _SECURITY_WEIGHT * _as_float(security.get("score"))
        + _ARCH_WEIGHT * _as_float(architecture.get("score")),
        1,
    )
    grade = calculate_grade(overall)

    return {
        "overall_score": overall,
        "grade": grade,
        "summary": _build_summary(overall, grade, security, architecture, repo_info, meta),
        "recommendations": _build_recommendations(security, architecture),
    }
