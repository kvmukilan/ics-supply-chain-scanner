"""Streamlit dashboard for ICS Supply Chain Vulnerability Scanner."""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st

from config import ScannerConfig
from inventory import load_inventory
from models import Finding
from scanner import ICSScanner

# --- Page Config ---
st.set_page_config(
    page_title="ICS Supply Chain Vulnerability Scanner",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# --- Custom CSS ---
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #1e293b, #334155);
        color: #fff;
        padding: 20px;
        border-radius: 12px;
        text-align: center;
    }
    .metric-card .value { font-size: 36px; font-weight: 700; }
    .metric-card .label { font-size: 13px; color: #94a3b8; margin-top: 4px; }
    .severity-critical { color: #dc2626; font-weight: 700; }
    .severity-high { color: #ea580c; font-weight: 700; }
    .severity-medium { color: #ca8a04; font-weight: 700; }
    .severity-low { color: #2563eb; font-weight: 700; }
    .kev-badge {
        background: #7c3aed; color: #fff; padding: 2px 8px;
        border-radius: 4px; font-size: 12px; font-weight: 600;
    }
    div[data-testid="stSidebar"] { background: #0f172a; }
    div[data-testid="stSidebar"] .stMarkdown { color: #e2e8f0; }
</style>
""", unsafe_allow_html=True)


SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#ca8a04",
    "LOW": "#2563eb",
    "NONE": "#6b7280",
}


def run_async(coro):
    """Run async function in sync context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def build_config_from_sidebar() -> ScannerConfig:
    """Build scanner config from sidebar inputs."""
    config = ScannerConfig()

    st.sidebar.header("API Configuration")
    nvd_key = st.sidebar.text_input(
        "NVD API Key (optional)", type="password", value=os.getenv("NVD_API_KEY", "")
    )
    if nvd_key:
        config.nvd.api_key = nvd_key

    st.sidebar.markdown("---")
    st.sidebar.subheader("Azure OpenAI (optional)")
    aoai_endpoint = st.sidebar.text_input("Endpoint", value=os.getenv("AZURE_OPENAI_ENDPOINT", ""))
    aoai_key = st.sidebar.text_input(
        "API Key", type="password", value=os.getenv("AZURE_OPENAI_API_KEY", "")
    )
    aoai_deployment = st.sidebar.text_input(
        "Deployment", value=os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    )

    if aoai_endpoint and aoai_key:
        config.llm.endpoint = aoai_endpoint
        config.llm.api_key = aoai_key
        config.llm.deployment = aoai_deployment
    else:
        config.llm.endpoint = ""
        config.llm.api_key = ""

    st.sidebar.markdown("---")
    st.sidebar.subheader("Risk Scoring Weights")

    col1, col2 = st.sidebar.columns(2)
    with col1:
        config.risk.purdue_weights[0] = st.number_input("L0/L1 weight", 0.5, 3.0, 1.5, 0.1)
        config.risk.purdue_weights[1] = config.risk.purdue_weights[0]
        config.risk.exposure_weights["internet"] = st.number_input("Internet exp.", 0.5, 3.0, 1.4, 0.1)
    with col2:
        config.risk.purdue_weights[4] = st.number_input("L4/L5 weight", 0.5, 3.0, 0.8, 0.1)
        config.risk.purdue_weights[5] = config.risk.purdue_weights[4]
        config.risk.kev_multiplier = st.number_input("KEV multiplier", 1.0, 3.0, 1.5, 0.1)

    return config


def render_summary(findings: list[Finding], total_assets: int):
    """Render dashboard summary metrics."""
    sev_counts = {}
    for f in findings:
        sev = f.ot_severity.value
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    kev_count = sum(1 for f in findings if f.in_kev)

    cols = st.columns(6)
    metrics = [
        ("Assets Scanned", total_assets, None),
        ("Total CVEs", len(findings), None),
        ("Critical", sev_counts.get("CRITICAL", 0), "#dc2626"),
        ("High", sev_counts.get("HIGH", 0), "#ea580c"),
        ("Medium", sev_counts.get("MEDIUM", 0), "#ca8a04"),
        ("In CISA KEV", kev_count, "#7c3aed"),
    ]

    for col, (label, value, color) in zip(cols, metrics, strict=True):
        with col:
            if color:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="value" style="color:{color}">{value}</div>
                    <div class="label">{label}</div>
                </div>""", unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="metric-card">
                    <div class="value">{value}</div>
                    <div class="label">{label}</div>
                </div>""", unsafe_allow_html=True)


def render_findings_table(findings: list[Finding]):
    """Render findings as a sortable dataframe."""
    if not findings:
        st.info("No findings to display.")
        return

    rows = []
    for f in sorted(findings, key=lambda x: x.ot_risk_score, reverse=True):
        rows.append({
            "OT Score": round(f.ot_risk_score, 2),
            "Severity": f.ot_severity.value,
            "CVE": f.cve.cve_id,
            "CVSS": f.cve.cvss_base_score,
            "KEV": "Yes" if f.in_kev else "",
            "Asset": f.asset.name,
            "Vendor": f.asset.vendor,
            "Model": f.asset.model,
            "Purdue": f.asset.purdue_level,
            "Exposure": f.asset.exposure.value,
            "Patch": f.asset.patch_status.value,
        })

    df = pd.DataFrame(rows)

    def color_severity(val):
        colors = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#ca8a04", "LOW": "#2563eb"}
        return f"color: {colors.get(val, '#6b7280')}; font-weight: 700"

    styled = df.style.applymap(color_severity, subset=["Severity"])
    st.dataframe(styled, use_container_width=True, height=400)


def render_finding_detail(finding: Finding):
    """Render detailed view of a single finding."""
    f = finding
    kev_tag = " 🔴 **CISA KEV**" if f.in_kev else ""

    st.markdown(f"### {f.cve.cve_id}{kev_tag}")
    st.markdown(
        f"**OT Risk Score: {f.ot_risk_score:.2f}** ({f.ot_severity.value}) | "
        f"CVSS Base: {f.cve.cvss_base_score}"
    )

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("**Asset Info**")
        st.text(f"Name:     {f.asset.name}")
        st.text(f"Vendor:   {f.asset.vendor} {f.asset.model}")
        st.text(f"Firmware: {f.asset.firmware_version}")
        st.text(f"CPE:      {f.asset.cpe}")
        st.text(f"Purdue:   Level {f.asset.purdue_level}")
        st.text(f"Zone:     {f.asset.network_zone}")
        st.text(f"Exposure: {f.asset.exposure.value}")
        st.text(f"Patch:    {f.asset.patch_status.value}")

    with col2:
        st.markdown("**Score Breakdown**")
        bd = f.score_breakdown
        st.text(f"Base CVSS:      {bd.get('base_cvss', 'N/A')}")
        st.text(f"Purdue Weight:  {bd.get('purdue_weight', 'N/A')}")
        st.text(f"Exposure:       {bd.get('exposure_weight', 'N/A')}")
        st.text(f"Patch Factor:   {bd.get('patch_weight', 'N/A')}")
        st.text(f"KEV Multiplier: {bd.get('kev_weight', 'N/A')}")
        st.text(f"Formula: {bd.get('formula', 'N/A')}")

    if f.in_kev and f.kev_entry:
        st.warning(
            f"**CISA KEV**: Added {f.kev_entry.date_added} | "
            f"Due: {f.kev_entry.due_date} | "
            f"Ransomware: {f.kev_entry.known_ransomware_use}\n\n"
            f"Required Action: {f.kev_entry.required_action}"
        )

    st.markdown("**Description**")
    st.text(f.cve.description)

    if f.iec_62443_mappings:
        st.markdown("**IEC 62443 Mappings**")
        for m in f.iec_62443_mappings:
            st.markdown(f"- `{m}`")

    if f.remediation:
        st.markdown("**Remediation Playbook**")
        rem = json.loads(f.remediation)
        for section in ["immediate_actions", "short_term_remediation", "long_term_remediation",
                        "compensating_controls", "verification_steps"]:
            items = rem.get(section, [])
            if items:
                st.markdown(f"*{section.replace('_', ' ').title()}:*")
                for item in items:
                    st.markdown(f"  - {item}")

    st.markdown(f"[View on NVD]({f.cve.nvd_url})")


def render_charts(findings: list[Finding]):
    """Render severity distribution and top assets charts."""
    if not findings:
        return

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("#### Severity Distribution")
        sev_data = {}
        for f in findings:
            sev = f.ot_severity.value
            sev_data[sev] = sev_data.get(sev, 0) + 1
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
        chart_df = pd.DataFrame([
            {"Severity": s, "Count": sev_data.get(s, 0)} for s in order if sev_data.get(s, 0) > 0
        ])
        if not chart_df.empty:
            st.bar_chart(chart_df.set_index("Severity"))

    with col2:
        st.markdown("#### Top 10 Riskiest Assets")
        asset_scores = {}
        for f in findings:
            name = f.asset.name
            if name not in asset_scores or f.ot_risk_score > asset_scores[name]:
                asset_scores[name] = f.ot_risk_score
        top_assets = sorted(asset_scores.items(), key=lambda x: x[1], reverse=True)[:10]
        if top_assets:
            chart_df = pd.DataFrame(top_assets, columns=["Asset", "Max OT Score"])
            st.bar_chart(chart_df.set_index("Asset"))


# --- Main App ---
def main():
    st.title("ICS Supply Chain Vulnerability Scanner")
    st.caption("OT Asset Inventory → NVD CVE → CISA KEV → OT Risk Scoring → IEC 62443 Remediation")

    config = build_config_from_sidebar()

    # File upload
    st.markdown("### Upload Asset Inventory")
    uploaded = st.file_uploader(
        "CSV or JSON inventory file",
        type=["csv", "json"],
        help="Required columns: name, vendor, model, firmware_version, cpe, purdue_level",
    )

    use_sample = st.checkbox("Use sample inventory (10 OT assets)")

    if st.button("Run Scan", type="primary", use_container_width=True):
        if not uploaded and not use_sample:
            st.error("Upload an inventory file or check 'Use sample inventory'.")
            return

        # Resolve inventory path
        if use_sample:
            inv_path = str(Path(__file__).parent / "sample_inventory.csv")
        else:
            suffix = Path(uploaded.name).suffix
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                tmp.write(uploaded.getvalue())
                inv_path = tmp.name

        # Run scan
        scanner = ICSScanner(config)
        with st.spinner("Running scan pipeline..."):
            progress = st.progress(0, text="Loading inventory...")
            try:
                assets = load_inventory(inv_path)
                progress.progress(20, text=f"Loaded {len(assets)} assets. Querying NVD...")

                result = run_async(scanner.scan(inv_path))
                progress.progress(100, text="Scan complete.")

            except Exception as e:
                st.error(f"Scan failed: {e}")
                return

        # Store results in session
        st.session_state["scan_result"] = result
        st.session_state["findings"] = result.findings

    # Render results
    if "scan_result" in st.session_state:
        result = st.session_state["scan_result"]
        findings = st.session_state["findings"]

        st.markdown("---")
        render_summary(findings, result.total_assets)
        st.markdown("---")
        render_charts(findings)
        st.markdown("---")

        # Findings table
        st.markdown("### Findings")

        # Filters
        fcol1, fcol2, fcol3 = st.columns(3)
        with fcol1:
            sev_filter = st.multiselect(
                "Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default=["CRITICAL", "HIGH"]
            )
        with fcol2:
            kev_only = st.checkbox("KEV only")
        with fcol3:
            min_score = st.slider("Min OT Score", 0.0, 10.0, 0.0, 0.5)

        filtered = [
            f for f in findings
            if f.ot_severity.value in sev_filter
            and (not kev_only or f.in_kev)
            and f.ot_risk_score >= min_score
        ]
        st.caption(f"Showing {len(filtered)} of {len(findings)} findings")
        render_findings_table(filtered)

        # Detail view
        st.markdown("### Finding Detail")
        if filtered:
            options = [
                f"{f.cve.cve_id} | {f.asset.name} | Score: {f.ot_risk_score:.2f}"
                for f in sorted(filtered, key=lambda x: x.ot_risk_score, reverse=True)
            ]
            selected = st.selectbox("Select finding", options)
            idx = options.index(selected)
            sorted_filtered = sorted(filtered, key=lambda x: x.ot_risk_score, reverse=True)
            render_finding_detail(sorted_filtered[idx])

        # Export
        st.markdown("---")
        st.markdown("### Export Reports")
        ecol1, ecol2 = st.columns(2)
        with ecol1:
            if st.button("Generate JSON Report"):
                from report import generate_json_report
                out_path = f"output/{result.scan_id}_report.json"
                Path("output").mkdir(exist_ok=True)
                generate_json_report(result, out_path)
                with open(out_path, encoding="utf-8") as f:
                    st.download_button("Download JSON", f.read(), file_name=f"{result.scan_id}_report.json")

        with ecol2:
            if st.button("Generate HTML Report"):
                from report import generate_html_report
                out_path = f"output/{result.scan_id}_report.html"
                Path("output").mkdir(exist_ok=True)
                generate_html_report(result, out_path)
                with open(out_path, encoding="utf-8") as f:
                    st.download_button("Download HTML", f.read(), file_name=f"{result.scan_id}_report.html")

        if result.errors:
            with st.expander(f"Warnings/Errors ({len(result.errors)})"):
                for e in result.errors:
                    st.warning(e)


if __name__ == "__main__":
    main()
