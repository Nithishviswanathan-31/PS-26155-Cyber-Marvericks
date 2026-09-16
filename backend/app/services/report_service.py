from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from io import BytesIO
from typing import Any

from ..domain.mapping import MappingVersion
from ..domain.remediation import SimulationResponse
from ..domain.schemas import AnalysisResponse
from ..domain.coverage import coverage_counts


class ReportGenerationError(ValueError):
    """Raised when a stored report data set cannot be rendered safely."""


def _text(value: Any) -> str:
    if value is None or value == "":
        return "Not available"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _paragraph(value: Any, style: Any) -> Any:
    from reportlab.platypus import Paragraph

    return Paragraph(escape(_text(value)).replace("\n", "<br/>"), style)


def _detail_table(rows: list[tuple[str, Any]], label_style: Any, value_style: Any) -> Any:
    from reportlab.platypus import Table, TableStyle
    from reportlab.lib import colors

    table = Table(
        [[_paragraph(label, label_style), _paragraph(value, value_style)] for label, value in rows],
        colWidths=[150, 350],
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e9f0f7")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c9d9")),
        ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e0ea")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _section_title(title: str, style: Any) -> Any:
    from reportlab.platypus import Paragraph, Spacer

    return [Spacer(1, 8), Paragraph(escape(title), style), Spacer(1, 8)]


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
            Preformatted,
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
    title_style = ParagraphStyle("ReportTitle", parent=styles["Title"], fontName="PS26155VeraBd", fontSize=20, leading=25, textColor=colors.HexColor("#12304a"), alignment=TA_CENTER, spaceAfter=12)
    section_style = ParagraphStyle("Section", parent=styles["Heading1"], fontName="PS26155VeraBd", fontSize=15, leading=19, textColor=colors.HexColor("#12304a"), spaceBefore=4, spaceAfter=8)
    sub_style = ParagraphStyle("Sub", parent=styles["Heading2"], fontName="PS26155VeraBd", fontSize=11, leading=14, textColor=colors.HexColor("#1f5477"), spaceBefore=6, spaceAfter=5)
    body_style = ParagraphStyle("Body", parent=styles["BodyText"], fontName="PS26155Vera", fontSize=9, leading=12, textColor=colors.HexColor("#263746"), spaceAfter=5)
    small_style = ParagraphStyle("Small", parent=body_style, fontSize=8, leading=10)
    label_style = ParagraphStyle("Label", parent=small_style, fontName="PS26155VeraBd")
    header_style = ParagraphStyle("Header", parent=small_style, fontName="PS26155VeraBd", textColor=colors.white, alignment=TA_CENTER)
    value_style = ParagraphStyle("Value", parent=small_style, fontName="PS26155Vera")
    mono_style = ParagraphStyle("Mono", parent=small_style, fontName="PS26155Vera", fontSize=7.5, leading=9)
    footer_style = ParagraphStyle("Footer", parent=small_style, fontSize=7, textColor=colors.HexColor("#607586"), alignment=TA_CENTER)

    def on_page(canvas: Any, document: Any) -> None:
        canvas.saveState()
        width, height = A4
        canvas.setStrokeColor(colors.HexColor("#b8c9d9"))
        canvas.line(18 * mm, height - 15 * mm, width - 18 * mm, height - 15 * mm)
        canvas.setFont("PS26155Vera", 7)
        canvas.setFillColor(colors.HexColor("#607586"))
        canvas.drawString(18 * mm, height - 11 * mm, "PS 26155 | CYBER MARVERICKS")
        canvas.drawRightString(width - 18 * mm, 10 * mm, f"Report {report_id} | Page {canvas.getPageNumber()}")
        canvas.restoreState()

    story: list[Any] = [Spacer(1, 26 * mm), Paragraph("AI-Driven Multi-Vendor Network Security Compliance Auditor", title_style), Paragraph("Evidence-First Compliance Report", sub_style), Spacer(1, 8)]
    story.extend(_section_title("1. Executive Summary", section_style))
    story.append(_detail_table([
        ("Vendor", analysis.vendor),
        ("Hostname", analysis.device.hostname),
        ("Device Model", analysis.device.device_model),
        ("Serial Number", analysis.device.serial_number),
        ("Configuration Version", analysis.device.version),
        ("Analysis ID", analysis.analysis_id),
        ("Analysis Date", "Not available in stored response"),
        ("Report Generated At", generated_at),
        ("Integrity Status", integrity.get("status") if integrity else "NOT VERIFIED"),
        ("Analysis Integrity Hash", integrity.get("analysis_hash") if integrity else "Not available"),
        ("Ledger Record", integrity.get("ledger_record_id") if integrity else "Not available"),
        ("Report Version", integrity.get("report_version") if integrity else "Not available"),
    ], label_style, value_style))
    story.append(Spacer(1, 12))
    counts = coverage_counts(analysis.results)
    story.append(Paragraph("Independent requirement totals; diagnostic children are listed below and excluded from these totals.", body_style))
    summary_data = [[_paragraph(state, header_style) for state in ("PASS", "FAIL", "UNKNOWN", "N/A")], [_paragraph(counts.get("PASS", 0), value_style), _paragraph(counts.get("FAIL", 0), value_style), _paragraph(counts.get("UNKNOWN", 0), value_style), _paragraph(counts.get("NOT_APPLICABLE", 0), value_style)]]
    summary_table = Table(summary_data, colWidths=[125, 125, 125, 125], hAlign="LEFT")
    summary_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12304a")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c9d9")), ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e0ea")), ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(summary_table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("Compliance decisions were produced by the deterministic control engine. AI-assisted mappings do not directly determine compliance.", body_style))
    story.append(PageBreak())

    story.extend(_section_title("2. Control Results", section_style))
    control_rows = [[_paragraph(value, header_style) for value in ("Control ID", "Control Name", "Result", "Evidence")]]
    for result in analysis.results:
        available = any(item.control_id == result.control_id for item in analysis.evidence)
        name = result.control_name + (f" (diagnostic of {result.diagnostic_of})" if result.diagnostic_of else "")
        control_rows.append([_paragraph(result.control_id, small_style), _paragraph(name, small_style), _paragraph(result.result.value, label_style), _paragraph("Available" if available else "Not available", small_style)])
    control_table = Table(control_rows, colWidths=[75, 245, 80, 100], repeatRows=1, hAlign="LEFT")
    control_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12304a")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#b8c9d9")), ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d5e0ea")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7)]))
    story.append(control_table)
    story.append(Spacer(1, 12))
    story.append(Paragraph("The table above reproduces stored control results. The report generator does not recalculate compliance.", body_style))
    story.append(PageBreak())

    story.extend(_section_title("3. Evidence Details", section_style))
    for index, evidence in enumerate(analysis.evidence, start=1):
        story.append(Paragraph(f"Evidence {index}: {escape(evidence.control_id or 'Control')} | {escape(evidence.property)}", sub_style))
        story.append(_detail_table([
            ("Control", f"{evidence.control_id or 'Not available'} | {evidence.control_name or 'Not available'}"),
            ("Property", evidence.property),
            ("Expected", evidence.expected),
            ("Actual", evidence.actual),
            ("Result", evidence.result.value),
            ("Source File", evidence.source_file),
            ("Line", f"{evidence.line_start}-{evidence.line_end}" if evidence.line_start is not None else "Not available"),
            ("Raw Excerpt", evidence.raw_excerpt),
            ("Explanation", evidence.explanation),
            ("Evidence Source", evidence.evidence_source),
        ], label_style, mono_style if evidence.raw_excerpt else value_style))
        story.append(Spacer(1, 8))
    if not analysis.evidence:
        story.append(Paragraph("No evidence records are available in the stored analysis.", body_style))

    story.append(PageBreak())
    story.extend(_section_title("4. Analysis Lineage", section_style))
    story.append(_detail_table([
        ("Parent Analysis", analysis.parent_analysis_id),
        ("Current Analysis", analysis.analysis_id),
        ("Re-analysis", "YES" if analysis.reanalyzed else "NO"),
        ("Mapping", analysis.mapping_id),
        ("Mapping Version", analysis.mapping_version),
    ], label_style, value_style))

    if analysis.reanalyzed or analysis.recognized_patterns or mapping is not None:
        story.extend(_section_title("5. Adaptive Mapping", section_style))
        recognized = analysis.recognized_patterns[0] if analysis.recognized_patterns else None
        mapping_values = mapping.approved_mapping if mapping and mapping.approved_mapping else {}
        story.append(_detail_table([
            ("Original Pattern", recognized.raw_pattern if recognized else "Not available"),
            ("Pattern ID", recognized.pattern_id if recognized else "Not available"),
            ("Mapping ID", mapping.mapping_id if mapping else analysis.mapping_id),
            ("Mapping Version", mapping.version if mapping else analysis.mapping_version),
            ("Mapping Status", mapping.status.value if mapping else "Not available"),
            ("Approval Status", "Human approved" if mapping and mapping.status.value == "APPROVED" else "Not available"),
            ("Recognized State", recognized.state if recognized else "Not available"),
            ("Approved Mapping", "; ".join(f"{key} = {_text(value)}" for key, value in mapping_values.items()) or "Not available"),
        ], label_style, value_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("The mapping was used to enrich the Security IR before deterministic evaluation. It does not independently prove compliance.", body_style))
        story.append(Paragraph("Original pattern evidence remains preserved separately from the approved mapping.", body_style))

    if simulation is not None:
        story.append(PageBreak())
        story.extend(_section_title("6. Remediation Simulation", section_style))
        changes = "; ".join(f"{change.property}: {_text(change.before_value)} -> {_text(change.after_value)}" for change in simulation.simulated_changes) or "Not available"
        story.append(_detail_table([
            ("Simulation ID", simulation.simulation_id),
            ("Parent Analysis", simulation.parent_analysis_id),
            ("Remediation ID", simulation.remediation_id),
            ("Control ID", simulation.control_id),
            ("Before Result", simulation.before_result.value),
            ("Simulated Changes", changes),
            ("After Result", simulation.after_result.value),
            ("Simulation Only", "YES" if simulation.simulation_only else "NO"),
        ], label_style, value_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph("SIMULATION ONLY - No production device was contacted or modified.", ParagraphStyle("Safety", parent=body_style, fontName="PS26155VeraBd", textColor=colors.HexColor("#9b2c2c"))))
        story.append(Paragraph("Simulation evidence is labeled SIMULATED_REMEDIATION and is distinct from configuration-source evidence.", body_style))
        story.append(Paragraph("Simulation Evidence", sub_style))
        if simulation.evidence:
            for index, evidence in enumerate(simulation.evidence, start=1):
                story.append(_detail_table([
                    ("Property", evidence.property),
                    ("Result", evidence.result.value),
                    ("Before", evidence.before_value),
                    ("After", evidence.after_value),
                    ("Evidence Source", evidence.evidence_source),
                    ("Original Source", evidence.original_source_file),
                ], label_style, mono_style if evidence.raw_excerpt else value_style))
                story.append(Spacer(1, 5))
        else:
            story.append(Paragraph("No simulation evidence records are available in the stored simulation result.", body_style))

    story.append(PageBreak())
    story.extend(_section_title("Final Disclaimer", section_style))
    story.append(Paragraph("This report represents the results of the implemented prototype controls and available evidence at the time of analysis.", body_style))
    story.append(Paragraph("UNKNOWN indicates that sufficient evidence was not available for a deterministic conclusion.", body_style))
    story.append(Paragraph("AI-assisted interpretation does not independently establish compliance.", body_style))
    story.append(Paragraph("Remediation demonstrated by this prototype is simulation-only. No production device configuration is modified.", body_style))
    story.append(Paragraph("This report is not a certification and does not represent every possible security control.", body_style))

    try:
        document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm, topMargin=22 * mm, bottomMargin=16 * mm, title="PS 26155 Evidence-First Compliance Report", author="CYBER MARVERICKS")
        document.build(story, onFirstPage=on_page, onLaterPages=on_page)
    except Exception as exc:
        raise ReportGenerationError("The PDF report could not be generated safely.") from exc
    return buffer.getvalue()
