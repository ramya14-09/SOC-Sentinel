
from io import BytesIO
from html import escape

import pandas as pd

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)


def generate_pdf_report(logs, alert_df):

    buffer = BytesIO()

    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#17365D"),
        fontSize=20,
        spaceAfter=10
    )

    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#17365D"),
        spaceBefore=12,
        spaceAfter=8
    )

    cell_style = ParagraphStyle(
        "TableCell",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        wordWrap="CJK"
    )

    elements = []

    # --------------------------------------------------
    # REPORT TITLE
    # --------------------------------------------------

    elements.append(
        Paragraph("SOC SENTINEL - SECURITY INVESTIGATION REPORT",
                  title_style)
    )

    elements.append(
        Paragraph(
            f"Report Generated: {pd.Timestamp.now().strftime('%d-%m-%Y %H:%M:%S')}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 15))

    # --------------------------------------------------
    # INVESTIGATION SUMMARY
    # --------------------------------------------------

    elements.append(
        Paragraph("1. Investigation Summary", heading_style)
    )

    total_attempts = len(logs)

    successful = (
        logs["status"].astype(str).str.upper() == "SUCCESS"
    ).sum()

    failed = (
        logs["status"].astype(str).str.upper() == "FAILED"
    ).sum()

    total_alerts = len(alert_df)

    critical = (
        alert_df["Risk Level"] == "CRITICAL"
    ).sum() if "Risk Level" in alert_df.columns else 0

    high = (
        alert_df["Risk Level"] == "HIGH"
    ).sum() if "Risk Level" in alert_df.columns else 0

    summary_data = [
        ["Metric", "Count"],
        ["Total Login Attempts", str(total_attempts)],
        ["Successful Logins", str(successful)],
        ["Failed Logins", str(failed)],
        ["Total Security Alerts", str(total_alerts)],
        ["Critical Risk Alerts", str(critical)],
        ["High Risk Alerts", str(high)]
    ]

    summary_table = Table(
        summary_data,
        colWidths=[100 * mm, 50 * mm]
    )

    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 7),
        ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke)
    ]))

    elements.append(summary_table)

    # --------------------------------------------------
    # LOGIN ACTIVITY
    # --------------------------------------------------

    elements.append(
        Paragraph("2. Login Activity Details", heading_style)
    )

    login_columns = [
        "timestamp",
        "user_id",
        "ip_address",
        "event_type",
        "status"
    ]

    login_data = [[
        "Timestamp",
        "User",
        "IP Address",
        "Event Type",
        "Status"
    ]]

    for _, row in logs.iterrows():

        login_data.append([
            str(row["timestamp"]),
            str(row["user_id"]),
            str(row["ip_address"]),
            str(row["event_type"]),
            str(row["status"])
        ])

    login_table = Table(
        [
            [Paragraph(escape(str(cell)), cell_style) for cell in row]
            for row in login_data
        ],
        colWidths=[45 * mm, 35 * mm, 45 * mm, 30 * mm, 25 * mm],
        repeatRows=1
    )

    login_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP")
    ]))

    elements.append(login_table)

    # --------------------------------------------------
    # SECURITY ALERTS
    # --------------------------------------------------

    elements.append(
        Paragraph("3. Detected Security Threats", heading_style)
    )

    alert_columns = [
        "Threat",
        "User",
        "IP Address",
        "Severity",
        "Details",
        "Risk Score",
        "Risk Level"
    ]

    available_columns = [
        col for col in alert_columns if col in alert_df.columns
    ]

    if not alert_df.empty and available_columns:

        alert_data = [
            available_columns
        ]

        for _, row in alert_df[available_columns].iterrows():
            alert_data.append([
                str(row[col]) for col in available_columns
            ])

        alert_table = Table(
            [
                [Paragraph(escape(str(cell)), cell_style) for cell in row]
                for row in alert_data
            ],
            repeatRows=1
        )

        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))

        elements.append(alert_table)

    else:
        elements.append(
            Paragraph("No security threats detected.", styles["Normal"])
        )

    # --------------------------------------------------
    # IP ADDRESS INVESTIGATION
    # --------------------------------------------------

    elements.append(
        Paragraph("4. IP Address Investigation Summary", heading_style)
    )

    if not logs.empty:

        ip_summary = logs.groupby("ip_address").agg(
            Total_Attempts=("status", "count"),
            Failed_Logins=(
                "status",
                lambda x: (x.astype(str).str.upper() == "FAILED").sum()
            ),
            Successful_Logins=(
                "status",
                lambda x: (x.astype(str).str.upper() == "SUCCESS").sum()
            )
        ).reset_index()

        ip_data = [[
            "IP Address",
            "Total Attempts",
            "Failed Logins",
            "Successful Logins"
        ]]

        for _, row in ip_summary.iterrows():
            ip_data.append([
                str(row["ip_address"]),
                str(row["Total_Attempts"]),
                str(row["Failed_Logins"]),
                str(row["Successful_Logins"])
            ])

        ip_table = Table(
            ip_data,
            colWidths=[65 * mm, 45 * mm, 45 * mm, 50 * mm],
            repeatRows=1
        )

        ip_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#17365D")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 6)
        ]))

        elements.append(ip_table)

    else:
        elements.append(
            Paragraph("No login records available.", styles["Normal"])
        )

    # --------------------------------------------------
    # BUILD PDF
    # --------------------------------------------------

    document.build(elements)

    pdf_bytes = buffer.getvalue()
    buffer.close()

    return pdf_bytes
