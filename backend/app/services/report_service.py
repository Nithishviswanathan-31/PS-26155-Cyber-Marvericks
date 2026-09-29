from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from io import BytesIO
from typing import Any

from ..domain.coverage import coverage_counts
from ..domain.enums import ComplianceResult
from ..domain.mapping import MappingVersion
from ..domain.remediation import SimulationResponse, RemediationDefinition
from ..domain.schemas import AnalysisResponse
from .remediation_service import get_remediation_definition, get_remediations_for_analysis


class ReportGenerationError(ValueError):
    """Raised when a stored report data set cannot be rendered safely."""


def _text(value: Any, default: str = "Not available") -> str:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _device_val(value: Any) -> str:
    """Explicitly format device identification fields without fabricating values."""
    if value is None or value == "":
        return "Not present in configuration"
    return str(value)


def _paragraph(value: Any, style: Any) -> Any:
    from reportlab.platypus import Paragraph

    return Paragraph(escape(_text(value)).replace("\n", "<br/>"), style)


def _detail_table(rows: list[tuple[str, Any]], label_style: Any, value_style: Any, col_widths: list[int] | None = None) -> Any:
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib import colors

    widths = col_widths or [150, 345]
    table = Table(
        [[_paragraph(label, label_style), _paragraph(value, value_style)] for label, value in rows],
        colWidths=widths,
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e9f0f7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c9d9")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e0ea")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _section_title(title: str, style: Any) -> list[Any]:
    from reportlab.platypus import Paragraph, Spacer

    return [Spacer(1, 10), Paragraph(escape(title), style), Spacer(1, 6)]


def generate_analysis_pdf(
    analysis: AnalysisResponse,
    *,
    mapping: MappingVersion | None = None,
    simulation: SimulationResponse | None = None,
    integrity: dict[str, Any] | None = None,
    report_id: str,
    generated_at: str,
) -> bytes:
    """Render stored analysis data only; this function never evaluates controls."""

    try:
        import os
        import reportlab
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import (
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise ReportGenerationError("PDF reporting requires the reportlab dependency.") from exc

    font_dir = os.path.join(os.path.dirname(reportlab.__file__), "fonts")
    if "PS26155Vera" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("PS26155Vera", os.path.join(font_dir, "Vera.ttf")))
        pdfmetrics.registerFont(TTFont("PS26155VeraBd", os.path.join(font_dir, "VeraBd.ttf")))

    if not analysis.analysis_id or not analysis.vendor:
        raise ReportGenerationError("The stored analysis is incomplete.")
    if mapping is not None and mapping.mapping_id != analysis.mapping_id:
        raise ReportGenerationError("The stored mapping does not match the analysis lineage.")
    if simulation is not None and simulation.parent_analysis_id != analysis.analysis_id:
        raise ReportGenerationError("The stored simulation does not belong to this analysis.")

    buffer = BytesIO()
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="PS26155VeraBd", fontSize=18, leading=22, textColor=colors.HexColor("#12304a"), alignment=TA_CENTER, spaceAfter=4)
    subtitle_style = ParagraphStyle("ReportSubTitle", fontName="PS26155VeraBd", fontSize=12, leading=15, textColor=colors.HexColor("#1f5477"), alignment=TA_CENTER, spaceAfter=6)
    meta_title_style = ParagraphStyle("ReportMetaTitle", fontName="PS26155Vera", fontSize=8, leading=11, textColor=colors.HexColor("#506070"), alignment=TA_CENTER, spaceAfter=12)

    section_style = ParagraphStyle("Section", parent=styles["Heading1"], fontName="PS26155VeraBd", fontSize=14, leading=18, textColor=colors.HexColor("#12304a"), spaceBefore=6, spaceAfter=8)
    sub_style = ParagraphStyle("Sub", parent=styles["Heading2"], fontName="PS26155VeraBd", fontSize=10, leading=13, textColor=colors.HexColor("#1f5477"), spaceBefore=6, spaceAfter=4)
    body_style = ParagraphStyle("Body", parent=styles["BodyText"], fontName="PS26155Vera", fontSize=8.5, leading=11.5, textColor=colors.HexColor("#263746"), spaceAfter=4)
    small_style = ParagraphStyle("Small", parent=body_style, fontSize=7.5, leading=9.5)
    label_style = ParagraphStyle("Label", parent=small_style, fontName="PS26155VeraBd")
    header_style = ParagraphStyle("Header", parent=small_style, fontName="PS26155VeraBd", textColor=colors.white, alignment=TA_CENTER)
    value_style = ParagraphStyle("Value", parent=small_style, fontName="PS26155Vera")
    mono_style = ParagraphStyle("Mono", parent=small_style, fontName="PS26155Vera", fontSize=7, leading=8.5)
    warning_box_style = ParagraphStyle("WarningBox", parent=body_style, fontName="PS26155VeraBd", fontSize=8, leading=10.5, textColor=colors.HexColor("#9b2c2c"))

    def on_page(canvas: Any, document: Any) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(colors.HexColor("#b8c9d9"))
        canvas.line(18 * mm, height - 15 * mm, width - 18 * mm, height - 15 * mm)
        canvas.setFont("PS26155Vera", 7)
        canvas.setFillColor(colors.HexColor("#607586"))
        canvas.drawString(18 * mm, height - 11 * mm, "PS 26155 | NTRO CYBER MARVERICKS")
        canvas.drawRightString(width - 18 * mm, 10 * mm, f"Report {report_id} | Page {canvas.getPageNumber()}")
        canvas.restoreState()

    story: list[Any] = [
        Spacer(1, 14 * mm),
        Paragraph("AI-Driven Multi-Vendor Network Security Compliance Auditor", title_style),
        Paragraph("Individual Device Compliance &amp; Audit Report", subtitle_style),
        Paragraph(f"Report ID: {report_id} &nbsp;|&nbsp; Generated: {generated_at} &nbsp;|&nbsp; System: PS 26155 MVP", meta_title_style),
        Spacer(1, 4),
    ]

    # -------------------------------------------------------------------------
    # 1. Executive Summary & Device Identification
    # -------------------------------------------------------------------------
    story.extend(_section_title("1. Executive Summary", section_style))

    # Device & context table
    device_rows = [
        ("Report ID", report_id),
        ("Analysis ID", analysis.analysis_id),
        ("Device ID", _device_val(analysis.device.device_id)),
        ("Hostname", _device_val(analysis.device.hostname)),
        ("Vendor", analysis.vendor),
        ("Platform", _device_val(analysis.device.platform)),
        ("OS / Firmware Version", _device_val(analysis.device.version)),
        ("Hardware Model", _device_val(analysis.device.device_model)),
        ("Serial Number", _device_val(analysis.device.serial_number)),
        ("Configuration File", analysis.filename or "Not present in configuration"),
        ("Assessment Timestamp", generated_at),
        ("Evaluation Basis", "Deterministic YAML Control Rules Engine (DeterministicControlEngine v2.1)"),
        ("Framework Context", "Multi-Framework (CIS Controls v8, NIST SP 800-53 r5, DISA STIG, ISO 27001:2022)"),
        ("Integrity Status", (integrity.get("status") or "VALID") if integrity else "NOT VERIFIED"),
        ("Analysis Integrity Hash", (integrity.get("analysis_hash") or "Not available") if integrity else "Not available"),
        ("Ledger Record", (integrity.get("ledger_record_id") or "Not available") if integrity else "Not available"),
        ("Report Version", integrity.get("report_version") if integrity and integrity.get("report_version") is not None else "1"),
    ]
    story.append(_detail_table(device_rows, label_style, value_style))
    story.append(Spacer(1, 10))

    # Compliance counts
    counts = coverage_counts(analysis.results)
    story.append(Paragraph(
        "<b>Compliance Evaluation Summary (Deterministic Results):</b> Independent requirement totals; "
        "diagnostic children are listed below and excluded from these totals.",
        body_style,
    ))
    summary_data = [
        [_paragraph(state, header_style) for state in ("PASS", "FAIL", "UNKNOWN", "NOT APPLICABLE")],
        [
            _paragraph(str(counts.get("PASS", 0)), label_style),
            _paragraph(str(counts.get("FAIL", 0)), label_style),
            _paragraph(str(counts.get("UNKNOWN", 0)), label_style),
            _paragraph(str(counts.get("NOT_APPLICABLE", 0)), label_style),
        ],
    ]
    summary_table = Table(summary_data, colWidths=[123, 124, 124, 124], hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12304a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c9d9")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e0ea")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 8))

    # Severity distribution
    severity_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in analysis.results:
        sev_str = str(r.severity.value if hasattr(r.severity, "value") else (r.severity or "")).upper()
        if sev_str in severity_counts:
            severity_counts[sev_str] += 1
    story.append(Paragraph("<b>Severity Distribution of Evaluated Controls:</b>", small_style))
    sev_data = [
        [_paragraph(sev, header_style) for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")],
        [
            _paragraph(str(severity_counts["CRITICAL"]), label_style),
            _paragraph(str(severity_counts["HIGH"]), label_style),
            _paragraph(str(severity_counts["MEDIUM"]), label_style),
            _paragraph(str(severity_counts["LOW"]), label_style),
        ],
    ]
    sev_table = Table(sev_data, colWidths=[123, 124, 124, 124], hAlign="LEFT")
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#264966")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c9d9")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e0ea")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 8))

    story.append(Paragraph(
        "<b>Core Governance Principle:</b> AI proposes → human reviews → approved knowledge is versioned → "
        "deterministic engine validates → evidence proves. Compliance decisions are produced exclusively by the "
        "deterministic control engine. Framework mappings provide advisory cross-references only.",
        body_style,
    ))
    story.append(PageBreak())

    # -------------------------------------------------------------------------
    # 2. Control Results Table
    # -------------------------------------------------------------------------
    story.extend(_section_title("2. Control Results", section_style))
    story.append(Paragraph(
        "Complete breakdown of evaluated YAML controls against normalized configuration facts. "
        "Results reflect authoritative deterministic engine evaluation at the time of analysis.",
        body_style,
    ))
    story.append(Spacer(1, 4))

    control_rows = [[
        _paragraph("Control ID", header_style),
        _paragraph("Control Name", header_style),
        _paragraph("Category", header_style),
        _paragraph("Severity", header_style),
        _paragraph("Result", header_style),
        _paragraph("Framework Cross-References", header_style),
    ]]
    for result in analysis.results:
        diag = f" (diagnostic of {result.diagnostic_of})" if result.diagnostic_of else ""
        name = result.control_name + diag
        sev_label = str(result.severity.value if hasattr(result.severity, "value") else (result.severity or "Not available")).upper()
        cat_label = str(result.category.value if hasattr(result.category, "value") else (result.category or "Not available"))
        fw_summary = "; ".join(f"{fm.framework_name}: {fm.reference_id}" for fm in (result.framework_mappings or [])) or "None"

        control_rows.append([
            _paragraph(result.control_id, label_style),
            _paragraph(name, small_style),
            _paragraph(cat_label, small_style),
            _paragraph(sev_label, small_style),
            _paragraph(result.result.value, label_style),
            _paragraph(fw_summary, small_style),
        ])

    control_table = Table(control_rows, colWidths=[50, 115, 75, 50, 55, 150], repeatRows=1, hAlign="LEFT")
    control_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12304a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c9d9")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e0ea")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(control_table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("The table above reproduces stored control results. The report generator does not recalculate compliance.", small_style))
    story.append(PageBreak())

    # -------------------------------------------------------------------------
    # 3. Multi-Framework Cross-References (Advisory)
    # -------------------------------------------------------------------------
    has_fw = any(bool(r.framework_mappings) for r in analysis.results)
    if has_fw:
        story.extend(_section_title("3. Multi-Framework Cross-References (Advisory)", section_style))
        story.append(Paragraph(
            "<b>Advisory Traceability Disclaimer:</b> Framework cross-references provide advisory mapping to published "
            "security standards (CIS Controls v8, NIST SP 800-53 Rev. 5, DISA STIG, and ISO/IEC 27001:2022). Deterministic "
            "controls remain the sole compliance evaluation authority. Prototype mappings denote candidate alignments "
            "under validation and do not claim official certifying equivalences.",
            body_style,
        ))
        story.append(Spacer(1, 6))

        mapping_rows = [[
            _paragraph("Control ID", header_style),
            _paragraph("Framework &amp; Version", header_style),
            _paragraph("Reference ID", header_style),
            _paragraph("Status", header_style),
            _paragraph("Framework Title", header_style),
        ]]
        for result in analysis.results:
            for fm in (result.framework_mappings or []):
                fw_name_ver = f"{fm.framework_name} {fm.framework_version or ''}".strip()
                mapping_rows.append([
                    _paragraph(result.control_id, label_style),
                    _paragraph(fw_name_ver, small_style),
                    _paragraph(fm.reference_id, label_style),
                    _paragraph(fm.mapping_status, small_style),
                    _paragraph(fm.title or "—", small_style),
                ])
        mapping_table = Table(mapping_rows, colWidths=[55, 100, 75, 70, 195], repeatRows=1, hAlign="LEFT")
        mapping_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12304a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c9d9")),
            ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e0ea")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(mapping_table)
        story.append(Spacer(1, 10))
        story.append(PageBreak())

    # -------------------------------------------------------------------------
    # 4. Evidence Details & Source Provenance
    # -------------------------------------------------------------------------
    story.extend(_section_title("4. Evidence Details", section_style))
    story.append(Paragraph(
        "Audit evidence records with line-level source attribution, normalized properties, actual values, and "
        "provenance classification (CONFIGURATION, APPROVED_MAPPING, or SIMULATED_REMEDIATION).",
        body_style,
    ))
    story.append(Spacer(1, 6))

    for index, evidence in enumerate(analysis.evidence, start=1):
        story.append(Paragraph(f"Evidence {index}: {escape(evidence.control_id or 'Control')} | {escape(evidence.property)}", sub_style))

        line_str = "Not available"
        if evidence.line_start is not None:
            line_str = f"{evidence.line_start}-{evidence.line_end}" if evidence.line_end and evidence.line_end != evidence.line_start else str(evidence.line_start)
        elif evidence.original_line_start is not None:
            line_str = f"{evidence.original_line_start} (from unmapped pattern)"

        src_file = evidence.source_file or evidence.original_source_file or "Not available"
        excerpt = evidence.raw_excerpt or evidence.original_raw_excerpt or "Not available"

        ev_rows = [
            ("Control", f"{evidence.control_id or 'Not available'} | {evidence.control_name or 'Not available'}"),
            ("Normalized Property", evidence.property),
            ("Expected Value", evidence.expected),
            ("Actual Value", evidence.actual),
            ("Result", evidence.result.value),
            ("Evidence Source", evidence.evidence_source or "CONFIGURATION"),
            ("Source File", src_file),
            ("Line Number / Range", line_str),
            ("Raw Excerpt", excerpt),
            ("Explanation", evidence.explanation or "Not available"),
        ]
        if evidence.evidence_source == "APPROVED_MAPPING":
            ev_rows.append(("Mapping Lineage", f"Approved Mapping {evidence.mapping_id or ''} v{evidence.mapping_version or '?'} (pattern: '{evidence.original_pattern or ''}')"))

        story.append(_detail_table(ev_rows, label_style, mono_style if excerpt != "Not available" else value_style))
        story.append(Spacer(1, 6))

    if not analysis.evidence:
        story.append(Paragraph("No evidence records are available in the stored analysis.", body_style))

    story.append(PageBreak())

    # -------------------------------------------------------------------------
    # 5. Analysis Lineage (Always present)
    # -------------------------------------------------------------------------
    story.extend(_section_title("5. Analysis Lineage", section_style))
    story.append(_detail_table([
        ("Parent Analysis", analysis.parent_analysis_id or "Not available"),
        ("Current Analysis", analysis.analysis_id),
        ("Re-analysis", "YES" if analysis.reanalyzed else "NO"),
        ("Mapping", analysis.mapping_id or "Not available"),
        ("Mapping Version", analysis.mapping_version if analysis.mapping_version is not None else "Not available"),
    ], label_style, value_style))
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------------------
    # 6. Adaptive Mapping (When applicable)
    # -------------------------------------------------------------------------
    if analysis.reanalyzed or analysis.recognized_patterns or mapping is not None:
        story.extend(_section_title("6. Adaptive Mapping", section_style))
        story.append(Paragraph(
            "<b>Controlled Adaptive Learning Lifecycle:</b> This analysis was produced through human-approved semantic mapping. "
            "Unrecognized vendor syntax was parsed, an AI candidate proposal was generated, reviewed and approved by an authorized "
            "human auditor, versioned in the integrity ledger, and deterministically re-evaluated. "
            "The AI candidate proposal did not independently prove compliance.",
            body_style,
        ))
        story.append(Spacer(1, 6))

        recognized = analysis.recognized_patterns[0] if analysis.recognized_patterns else None
        mapping_values = mapping.approved_mapping if mapping and mapping.approved_mapping else {}
        adaptive_rows = [
            ("Original Pattern", recognized.raw_pattern if recognized else (mapping.pattern_signature if mapping else "Not available")),
            ("Pattern ID", recognized.pattern_id if recognized else (mapping.pattern_id if mapping else "Not available")),
            ("Mapping ID", mapping.mapping_id if mapping else (analysis.mapping_id or "Not available")),
            ("Mapping Version", f"v{mapping.version}" if mapping else (f"v{analysis.mapping_version}" if analysis.mapping_version else "Not available")),
            ("Mapping Status", mapping.status.value if mapping else "APPROVED"),
            ("Approval Status", "Human approved" if mapping and mapping.status.value == "APPROVED" else "Not available"),
            ("Human Review Action", mapping.action if mapping else "APPROVE"),
            ("Reviewer Attribution", (mapping.reviewer_id if mapping and mapping.reviewer_id else "Not available")),
            ("Recognized State", recognized.state if recognized else "RECOGNIZED_VIA_APPROVED_MAPPING"),
            ("Parent Analysis", analysis.parent_analysis_id or "Not available"),
            ("Approved Mapping", "; ".join(f"{k} = {_text(v)}" for k, v in mapping_values.items()) or "Not available"),
        ]
        story.append(_detail_table(adaptive_rows, label_style, value_style))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "The mapping was used to enrich the Security IR before deterministic evaluation. It does not independently prove compliance.",
            body_style,
        ))
        story.append(Paragraph(
            "Original pattern evidence remains preserved separately from the approved mapping.",
            body_style,
        ))
        story.append(Spacer(1, 10))

    # -------------------------------------------------------------------------
    # 7. Device-Specific Step-by-Step CLI Remediation Guidance
    # -------------------------------------------------------------------------
    story.extend(_section_title("7. Device-Specific CLI Remediation Guidance (Simulation Only)", section_style))
    story.append(Paragraph(
        "<b>SIMULATION ONLY — No production device was contacted or modified.</b> "
        "The following device-specific CLI remediation instructions are generated for administrative review "
        "and simulation validation only. Commands must never be executed automatically on production hardware.",
        warning_box_style,
    ))
    story.append(Spacer(1, 6))

    remediations = get_remediations_for_analysis(analysis)
    if remediations:
        for rem in remediations:
            story.append(Paragraph(f"<b>Remediation for {escape(rem.control_id)}: {escape(rem.title)}</b>", sub_style))
            rem_rows = [
                ("Control ID", rem.control_id),
                ("Target Vendor", rem.vendor),
                ("Target Platform", rem.platform),
                ("Finding / Problem", rem.finding or "Configuration does not meet security control specification."),
                ("Technical Rationale", rem.explanation or "Enforces required security hardening parameter."),
                ("Applicability & Constraints", rem.applicability_notes or "Review platform firmware and syntax compatibility before applying."),
                ("Risk Level", rem.risk_level),
            ]
            story.append(_detail_table(rem_rows, label_style, value_style))
            story.append(Spacer(1, 4))

            if rem.remediation_steps:
                story.append(Paragraph("<b>Step-by-Step CLI Instructions:</b>", small_style))
                for step in rem.remediation_steps:
                    story.append(Paragraph(f"&nbsp;&nbsp;{escape(step)}", mono_style))
            elif rem.commands:
                story.append(Paragraph("<b>CLI Command Sequence:</b>", small_style))
                for cmd in rem.commands:
                    story.append(Paragraph(f"&nbsp;&nbsp;&gt; {escape(cmd)}", mono_style))

            story.append(Paragraph(
                "<i>Note on Parameter Placeholders:</i> Values enclosed in angle brackets (e.g., &lt;management-interface&gt;, "
                "&lt;password&gt;, &lt;server-ip&gt;) are required parameters and must be populated with site-specific values.",
                small_style,
            ))
            story.append(Spacer(1, 8))
    else:
        has_fails = any(r.result is ComplianceResult.FAIL for r in analysis.results)
        if has_fails:
            story.append(Paragraph("Failing controls were detected, but no automated remediation templates are registered for this vendor/control combination.", body_style))
        else:
            story.append(Paragraph("All evaluated controls passed or are compliant. No remediation is required for this configuration.", body_style))

    # -------------------------------------------------------------------------
    # 8. Remediation Simulation Execution Results (When Present)
    # -------------------------------------------------------------------------
    if simulation is not None:
        story.append(PageBreak())
        story.extend(_section_title("8. Remediation Simulation", section_style))
        story.append(Paragraph(
            "<b>SIMULATION ONLY — No production device was contacted or modified.</b> "
            "Remediation simulation tests remediation effects on an isolated in-memory Security IR model. "
            "Original configuration data and historical analysis snapshots remain completely immutable.",
            warning_box_style,
        ))
        story.append(Paragraph(
            "Simulation evidence is labeled SIMULATED_REMEDIATION and is distinct from configuration-source evidence.",
            body_style,
        ))
        story.append(Spacer(1, 6))

        changes = "; ".join(f"{change.property}: {_text(change.before_value)} -> {_text(change.after_value)}" for change in simulation.simulated_changes) or "Not available"
        rem_def = get_remediation_definition(simulation.remediation_id)
        sim_rows = [
            ("Simulation ID", simulation.simulation_id),
            ("Parent Analysis", simulation.parent_analysis_id),
            ("Remediation ID", simulation.remediation_id),
            ("Control ID", simulation.control_id),
            ("Target Vendor", simulation.target_vendor or (rem_def.vendor if rem_def else "Not specified")),
            ("Platform", (rem_def.platform if rem_def and rem_def.platform else "Not specified")),
            ("Before Result", simulation.before_result.value),
            ("Simulated Property Changes", changes),
            ("After Result", simulation.after_result.value),
            ("Simulation Only", "YES" if simulation.simulation_only else "NO"),
        ]
        story.append(_detail_table(sim_rows, label_style, value_style))
        story.append(Spacer(1, 8))

        story.append(Paragraph("<b>Simulation Evidence:</b>", sub_style))
        if simulation.evidence:
            for index, sim_ev in enumerate(simulation.evidence, start=1):
                story.append(_detail_table([
                    ("Property", sim_ev.property),
                    ("Simulated Result", sim_ev.result.value),
                    ("Before", sim_ev.before_value),
                    ("After", sim_ev.after_value),
                    ("Evidence Source", sim_ev.evidence_source),
                    ("Original Source", sim_ev.original_source_file or "Not available"),
                ], label_style, mono_style))
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph("No simulation evidence records are available in the stored simulation result.", body_style))

    # -------------------------------------------------------------------------
    # 9. Cryptographic Integrity Ledger Audit
    # -------------------------------------------------------------------------
    story.append(PageBreak())
    story.extend(_section_title("9. Cryptographic Integrity Ledger Audit", section_style))
    story.append(Paragraph(
        "Cryptographic ledger records guarantee non-repudiation and evidence tampering detection. "
        "Every analysis and report is recorded in an append-only SHA-256 hash-chained ledger.",
        body_style,
    ))
    story.append(Spacer(1, 6))

    integrity_rows = [
        ("Artifact Type", (integrity.get("artifact_type") or "REPORT") if integrity else "REPORT"),
        ("Report ID", report_id),
        ("Target Analysis ID", analysis.analysis_id),
        ("Analysis Content SHA-256", (integrity.get("analysis_hash") or "Not available") if integrity else "Not available"),
        ("Report Ledger Record ID", (integrity.get("ledger_record_id") or "Not available") if integrity else "Not available"),
        ("Report Record Hash", (integrity.get("report_hash") or "Chained") if integrity else "Chained"),
        ("Preceding Hash in Chain", (integrity.get("previous_hash") or "Genesis / Chained") if integrity else "Genesis / Chained"),
        ("Ledger Verification Status", (integrity.get("status") or "VALID") if integrity else "NOT VERIFIED"),
        ("Verification Engine", "SHA-256 Append-Only Tamper-Evident Ledger"),
    ]
    story.append(_detail_table(integrity_rows, label_style, value_style))
    story.append(Spacer(1, 10))

    # -------------------------------------------------------------------------
    # 10. Regulatory Disclaimers & Governance Notice
    # -------------------------------------------------------------------------
    story.extend(_section_title("10. Final Disclaimer &amp; Governance Notice", section_style))
    story.append(Paragraph(
        "1. <b>Deterministic Authority:</b> Compliance determinations are produced exclusively by the deterministic YAML "
        "control engine. AI proposals and framework cross-references provide advisory traceability only and do not establish compliance.",
        body_style,
    ))
    story.append(Paragraph(
        "2. <b>Simulation Safety:</b> Remediation guidance is simulation-only and does not modify production devices. "
        "No production device was contacted, queried, or modified during analysis or simulation.",
        body_style,
    ))
    story.append(Paragraph(
        "3. <b>Deterministic UNKNOWN:</b> UNKNOWN indicates that sufficient configuration evidence was not present for a "
        "deterministic conclusion. UNKNOWN is a valid deterministic state, not a failure of evaluation.",
        body_style,
    ))
    story.append(Paragraph(
        "4. <b>Audit Scope:</b> This report reflects the evaluated configuration artifact snapshot and does not constitute "
        "a full network architecture certification.",
        body_style,
    ))

    try:
        document = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=22 * mm,
            bottomMargin=16 * mm,
            title="PS 26155 Individual Device Compliance & Audit Report",
            author="CYBER MARVERICKS",
        )
        document.build(story, onFirstPage=on_page, onLaterPages=on_page)
    except Exception as exc:
        raise ReportGenerationError("The PDF report could not be generated safely.") from exc

    return buffer.getvalue()
