
import streamlit as st
import pandas as pd
import plotly.express as px
import ipaddress

from datetime import datetime

from streamlit_autorefresh import st_autorefresh

from src.log_parser import load_logs
from src.detection_engine import detect_threats
from src.risk_scoring import process_alerts
from src.report_generator import generate_pdf_report
from src.response_recommendations import get_recommendation

from src.incident_database import (
    initialize_database,
    save_incident,
    get_all_incidents
)


# --------------------------------------------------
# PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SOC Sentinel",
    page_icon="🛡️",
    layout="wide"
)


# --------------------------------------------------
# LOGIN AUTHENTICATION
# --------------------------------------------------

USERNAME = "admin"
PASSWORD = "admin123"

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:

    st.title("🛡️ SOC Sentinel")
    st.subheader("Security Operations Center")

    st.markdown("### Analyst Login")

    username = st.text_input("Username")

    password = st.text_input(
        "Password",
        type="password"
    )

    if st.button("Login", use_container_width=True):

        if username == USERNAME and password == PASSWORD:

            st.session_state.logged_in = True
            st.rerun()

        else:
            st.error("Invalid username or password.")

    st.info("Demo credentials: admin / admin123")

    st.stop()


# --------------------------------------------------
# INITIALIZE INCIDENT DATABASE
# --------------------------------------------------

initialize_database()


# --------------------------------------------------
# SIDEBAR
# --------------------------------------------------

st.sidebar.title("🛡️ SOC Sentinel")
st.sidebar.success("Analyst Logged In")
st.sidebar.write("Welcome, Admin")


# --------------------------------------------------
# LIVE MONITORING SETTINGS
# --------------------------------------------------

st.sidebar.divider()

st.sidebar.subheader("⚡ Live Monitoring")

auto_refresh = st.sidebar.checkbox(
    "Enable Auto Refresh",
    value=False
)

if auto_refresh:

    st_autorefresh(
        interval=10000,
        limit=None,
        key="soc_live_refresh"
    )

    st.sidebar.success("Monitoring Active")

else:

    st.sidebar.info("Auto Refresh Disabled")


if st.sidebar.button("Logout"):

    st.session_state.logged_in = False
    st.rerun()


# --------------------------------------------------
# INITIALIZE SIMULATED EVENTS
# --------------------------------------------------

if "simulated_events" not in st.session_state:
    st.session_state.simulated_events = []


# --------------------------------------------------
# LOAD SECURITY DATA
# --------------------------------------------------

base_logs = load_logs("data/sample_auth_logs.csv")

simulated_logs = pd.DataFrame(
    st.session_state.simulated_events,
    columns=base_logs.columns
)

logs = pd.concat(
    [base_logs, simulated_logs],
    ignore_index=True
)

logs["timestamp"] = pd.to_datetime(
    logs["timestamp"]
)

logs = logs.sort_values(
    "timestamp"
).reset_index(drop=True)


# --------------------------------------------------
# DETECT THREATS AND CALCULATE RISK SCORES
# --------------------------------------------------

alerts = detect_threats(logs)

scored_alerts = process_alerts(alerts)

alert_df = pd.DataFrame(scored_alerts)

if alert_df.empty:

    alert_df = pd.DataFrame(
        columns=[
            "Threat",
            "User",
            "IP Address",
            "Severity",
            "Details",
            "Risk Score",
            "Risk Level"
        ]
    )


# --------------------------------------------------
# DASHBOARD HEADER
# --------------------------------------------------

st.title("🛡️ SOC Sentinel Dashboard")

st.caption(
    "Security Operations Center | "
    "Threat Detection and Risk Monitoring"
)

st.divider()


# --------------------------------------------------
# SECURITY ALERT SUMMARY
# --------------------------------------------------

st.header("📊 Security Alert Summary")

total_alerts = len(alert_df)

risk_levels = alert_df["Risk Level"]

critical_alerts = (risk_levels == "CRITICAL").sum()
high_alerts = (risk_levels == "HIGH").sum()
medium_alerts = (risk_levels == "MEDIUM").sum()
low_alerts = (risk_levels == "LOW").sum()

col1, col2, col3, col4, col5 = st.columns(5)

col1.metric("Total Alerts", total_alerts)
col2.metric("🔴 Critical", critical_alerts)
col3.metric("🟠 High", high_alerts)
col4.metric("🟡 Medium", medium_alerts)
col5.metric("🟢 Low", low_alerts)

st.divider()


# --------------------------------------------------
# LOGIN STATISTICS
# --------------------------------------------------

st.header("📈 Login Statistics")

total_attempts = len(logs)

successful_logins = (
    logs["status"] == "SUCCESS"
).sum()

failed_logins = (
    logs["status"] == "FAILED"
).sum()

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Login Attempts", total_attempts)
col2.metric("Successful Logins", successful_logins)
col3.metric("Failed Logins", failed_logins)
col4.metric("Security Alerts", total_alerts)

st.divider()


# --------------------------------------------------
# LATEST LOGIN EVENTS
# --------------------------------------------------

st.header("🕒 Latest Login Events")

latest_events = logs.sort_values(
    "timestamp",
    ascending=False
).head(10)

st.dataframe(
    latest_events,
    use_container_width=True,
    hide_index=True
)


# --------------------------------------------------
# INTERACTIVE LOGIN ATTACK SIMULATOR
# --------------------------------------------------

st.header("🧪 Interactive Attack Simulator")

st.write(
    "Enter login credentials to simulate an authentication event."
)

with st.expander("Generate a Login Event", expanded=True):

    with st.form("login_simulator"):

        test_user = st.text_input(
            "Username",
            placeholder="Enter username"
        )

        test_password = st.text_input(
            "Password",
            type="password",
            placeholder="Enter password"
        )

        test_ip = st.text_input(
            "IP Address",
            value="198.51.100.77"
        )

        submitted = st.form_submit_button(
            "Simulate Login",
            use_container_width=True
        )

    if submitted:

        if not test_user.strip():

            st.error("Please enter a username.")

        else:

            try:

                ipaddress.ip_address(test_ip.strip())

                if (
                    test_user == USERNAME
                    and test_password == PASSWORD
                ):

                    login_status = "SUCCESS"

                else:

                    login_status = "FAILED"

                new_event = {
                    "timestamp": datetime.now(),
                    "user_id": test_user.strip(),
                    "ip_address": test_ip.strip(),
                    "event_type": "LOGIN",
                    "status": login_status
                }

                st.session_state.simulated_events.append(
                    new_event
                )

                if login_status == "SUCCESS":

                    st.session_state.login_message = (
                        "Login Successful!"
                    )

                else:

                    st.session_state.login_message = (
                        "Login Failed! Invalid credentials."
                    )

                st.rerun()

            except ValueError:

                st.error("Please enter a valid IP address.")


# --------------------------------------------------
# DISPLAY AUTHENTICATION RESULT
# --------------------------------------------------

if "login_message" in st.session_state:

    if st.session_state.login_message == "Login Successful!":

        st.success(st.session_state.login_message)

    else:

        st.error(st.session_state.login_message)

    del st.session_state.login_message


# --------------------------------------------------
# DISPLAY GENERATED EVENTS
# --------------------------------------------------

st.subheader("Generated Login Events")

if st.session_state.simulated_events:

    simulated_df = pd.DataFrame(
        st.session_state.simulated_events
    )

    st.dataframe(
        simulated_df,
        use_container_width=True,
        hide_index=True
    )

    if st.button("Clear Simulated Events"):

        st.session_state.simulated_events = []
        st.rerun()

else:

    st.info("No simulated login events yet.")


st.divider()


# --------------------------------------------------
# SECURITY ALERT INVESTIGATION
# --------------------------------------------------

st.header("🔎 Security Alert Investigation")

if not alert_df.empty:

    risk_options = ["All"] + sorted(
        alert_df["Risk Level"].dropna().unique().tolist()
    )

    threat_options = ["All"] + sorted(
        alert_df["Threat"].dropna().unique().tolist()
    )

    col1, col2 = st.columns(2)

    with col1:

        selected_risk = st.selectbox(
            "Filter by Risk Level",
            risk_options
        )

    with col2:

        selected_threat = st.selectbox(
            "Filter by Threat",
            threat_options
        )

    filtered_alerts = alert_df.copy()

    if selected_risk != "All":

        filtered_alerts = filtered_alerts[
            filtered_alerts["Risk Level"] == selected_risk
        ]

    if selected_threat != "All":

        filtered_alerts = filtered_alerts[
            filtered_alerts["Threat"] == selected_threat
        ]

    st.subheader("Detected Security Alerts")

    st.dataframe(
        filtered_alerts,
        use_container_width=True,
        hide_index=True
    )


    # --------------------------------------------------
    # INCIDENT RESPONSE RECOMMENDATIONS
    # --------------------------------------------------

    st.divider()

    st.header("🚨 Incident Response Recommendations")

    if not filtered_alerts.empty:

        for index, alert in filtered_alerts.iterrows():

            threat = alert["Threat"]
            user = alert["User"]
            ip_address = alert["IP Address"]

            recommendation = get_recommendation(threat)

            with st.expander(
                f"🔍 {threat} | User: {user} | IP: {ip_address}"
            ):

                st.write(
                    "**Priority:**",
                    recommendation["Priority"]
                )

                st.write(
                    "**Recommended Action:**",
                    recommendation["Action"]
                )

                st.markdown("**Steps to Resolve:**")

                for step in recommendation["Steps"]:

                    st.markdown(f"- {step}")

    else:

        st.info("No alerts available for recommendations.")

else:

    st.success("No security threats detected in the system.")


# --------------------------------------------------
# INCIDENT RESPONSE TRACKING - SQLITE
# --------------------------------------------------

st.divider()

st.header("📋 Incident Response Tracking")

# Load previously saved incidents

saved_incidents = get_all_incidents()

if not saved_incidents.empty:

    saved_statuses = dict(
        zip(
            saved_incidents["Incident ID"],
            saved_incidents["Status"]
        )
    )

else:

    saved_statuses = {}


if not alert_df.empty:

    st.subheader("Update Incident Status")

    status_options = [
        "Open",
        "Investigating",
        "Resolved"
    ]

    for index, alert in alert_df.iterrows():

        threat = str(alert["Threat"])
        user = str(alert["User"])
        ip_address = str(alert["IP Address"])
        details = str(alert.get("Details", ""))

        # Generate a stable incident ID

        incident_id = (
            f"{threat}|{user}|{ip_address}|{details}"
        )

        risk_level = str(
            alert.get("Risk Level", "MEDIUM")
        )

        risk_score = pd.to_numeric(
            alert.get("Risk Score", 0),
            errors="coerce"
        )

        risk_score = (
            int(risk_score)
            if pd.notna(risk_score)
            else 0
        )

        current_status = saved_statuses.get(
            incident_id,
            "Open"
        )

        with st.expander(
            f"🚨 {threat} | {user} | {ip_address}"
        ):

            st.write("**Threat:**", threat)
            st.write("**Affected User:**", user)
            st.write("**IP Address:**", ip_address)
            st.write("**Risk Level:**", risk_level)
            st.write("**Risk Score:**", risk_score)

            selected_status = st.selectbox(
                "Incident Status",
                options=status_options,
                index=(
                    status_options.index(current_status)
                    if current_status in status_options
                    else 0
                ),
                key=f"sqlite_status_{index}"
            )

            # Save incident status in SQLite

            save_incident(
                incident_id=incident_id,
                threat=threat,
                user=user,
                ip_address=ip_address,
                risk_level=risk_level,
                risk_score=risk_score,
                status=selected_status
            )

else:

    st.info("No new security incidents currently detected.")


# --------------------------------------------------
# DATABASE INCIDENT SUMMARY
# --------------------------------------------------

st.divider()

st.subheader("📊 Saved Incident Summary")

database_incidents = get_all_incidents()

if not database_incidents.empty:

    open_count = (
        database_incidents["Status"] == "Open"
    ).sum()

    investigating_count = (
        database_incidents["Status"] == "Investigating"
    ).sum()

    resolved_count = (
        database_incidents["Status"] == "Resolved"
    ).sum()

    col1, col2, col3 = st.columns(3)

    col1.metric("Open Incidents", int(open_count))
    col2.metric("Investigating", int(investigating_count))
    col3.metric("Resolved", int(resolved_count))

    st.subheader("All Saved Incidents")

    st.dataframe(
        database_incidents,
        use_container_width=True,
        hide_index=True
    )

else:

    st.info("No incidents have been saved in the database yet.")


# --------------------------------------------------
# IP ADDRESS INVESTIGATION
# --------------------------------------------------

st.divider()

st.header("🔍 IP Address Investigation")

ip_list = sorted(
    logs["ip_address"].dropna().astype(str).unique().tolist()
)

if ip_list:

    selected_ip = st.selectbox(
        "Select an IP Address",
        ["Select an IP Address"] + ip_list
    )

    if selected_ip != "Select an IP Address":

        ip_logs = logs[
            logs["ip_address"] == selected_ip
        ]

        total_ip_attempts = len(ip_logs)

        failed_attempts = (
            ip_logs["status"] == "FAILED"
        ).sum()

        successful_attempts = (
            ip_logs["status"] == "SUCCESS"
        ).sum()

        col1, col2, col3 = st.columns(3)

        col1.metric("Total Login Attempts", total_ip_attempts)
        col2.metric("Failed Logins", failed_attempts)
        col3.metric("Successful Logins", successful_attempts)

        st.subheader("Login Activity")

        st.dataframe(
            ip_logs,
            use_container_width=True,
            hide_index=True
        )

        matching_alerts = alert_df[
            alert_df["IP Address"] == selected_ip
        ]

        st.subheader("Detected Security Threats")

        if not matching_alerts.empty:

            st.dataframe(
                matching_alerts,
                use_container_width=True,
                hide_index=True
            )

        else:

            st.success(
                "No security threats detected for this IP address."
            )

else:

    st.info("No IP addresses available.")


st.divider()


# --------------------------------------------------
# RISK LEVEL DISTRIBUTION
# --------------------------------------------------

st.header("📊 Risk Level Distribution")

if total_alerts > 0:

    risk_counts = (
        alert_df["Risk Level"]
        .value_counts()
        .reset_index()
    )

    risk_counts.columns = ["Risk Level", "Count"]

    fig = px.pie(
        risk_counts,
        names="Risk Level",
        values="Count",
        title="Security Alerts by Risk Level",
        hole=0.4
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

else:

    st.info("No risk data available.")


st.divider()


# --------------------------------------------------
# LOGIN STATUS ANALYSIS
# --------------------------------------------------

st.header("📈 Login Status Analysis")

status_counts = (
    logs["status"]
    .value_counts()
    .reset_index()
)

status_counts.columns = ["Status", "Count"]

fig2 = px.bar(
    status_counts,
    x="Status",
    y="Count",
    color="Status",
    title="Successful vs Failed Login Attempts",
    text="Count"
)

st.plotly_chart(
    fig2,
    use_container_width=True
)


st.divider()


# --------------------------------------------------
# RISK SCORE ANALYSIS
# --------------------------------------------------

st.header("⚠️ Risk Score Analysis")

if total_alerts > 0 and "Risk Score" in alert_df.columns:

    fig3 = px.bar(
        alert_df,
        x="Threat",
        y="Risk Score",
        color="Risk Level",
        title="Threat Risk Scores",
        text="Risk Score"
    )

    st.plotly_chart(
        fig3,
        use_container_width=True
    )

else:

    st.info("No risk score data available.")


st.divider()


# --------------------------------------------------
# DOWNLOAD SECURITY REPORT
# --------------------------------------------------

st.header("📥 Download Security Report")

if total_alerts > 0:

    # DOWNLOAD CSV REPORT

    csv_data = alert_df.to_csv(
        index=False
    ).encode("utf-8")

    st.download_button(
        label="Download Security Alerts CSV",
        data=csv_data,
        file_name="SOC_Sentinel_Security_Report.csv",
        mime="text/csv",
        use_container_width=True
    )

    # DOWNLOAD PDF INVESTIGATION REPORT

    st.subheader("📄 Download Complete Investigation Report")

    pdf_report = generate_pdf_report(
        logs,
        alert_df
    )

    st.download_button(
        label="Download PDF Security Report",
        data=pdf_report,
        file_name="SOC_Sentinel_Investigation_Report.pdf",
        mime="application/pdf",
        use_container_width=True
    )

else:

    st.info("No security alerts available for download.")


# --------------------------------------------------
# FOOTER
# --------------------------------------------------

st.divider()

st.caption(
    "SOC Sentinel | Cybersecurity Threat Detection "
    "and Risk Monitoring Project"
)
