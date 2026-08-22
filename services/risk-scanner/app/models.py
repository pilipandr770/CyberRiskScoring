import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db import Base


def _uuid() -> str:
    return str(uuid.uuid4())


class AgentUser(Base):
    __tablename__ = "agent_users"

    id = Column(String, primary_key=True, default=_uuid)
    username = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    display_name = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ClientAssessment(Base):
    __tablename__ = "client_assessments"

    id = Column(String, primary_key=True, default=_uuid)
    agent_id = Column(String, ForeignKey("agent_users.id"), nullable=False)

    company_name = Column(String, nullable=False)
    hrb_number = Column(String, nullable=True)
    domain = Column(String, nullable=False)
    industry = Column(String, nullable=False)
    employee_band = Column(String, nullable=True)
    contact_email = Column(String, nullable=True)  # needed so M3 provisioning has somewhere to send access
    annual_turnover_eur = Column(Float, nullable=True)
    office_ip = Column(String, nullable=True)  # Tier 1 trigger

    prior_incident = Column(String, nullable=True)       # "yes"/"no"
    prior_incident_notes = Column(Text, nullable=True)
    has_mfa = Column(String, nullable=True)               # "yes"/"no"/"unknown"
    has_tested_backups = Column(String, nullable=True)    # "yes"/"no"/"unknown"
    existing_cyber_insurance = Column(String, nullable=True)  # "yes"/"no"

    consent_confirmed = Column(String, nullable=False, default="no")

    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanResult", back_populates="assessment")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True, default=_uuid)
    assessment_id = Column(String, ForeignKey("client_assessments.id"), nullable=False)

    status = Column(String, default="pending")  # pending/running/done/error
    tier = Column(String, nullable=True)          # "Tier 0" / "Tier 1"

    raw_findings_json = Column(Text, nullable=True)
    raw_score = Column(Float, nullable=True)
    multiplier = Column(Float, nullable=True)
    expected_damage_eur = Column(Float, nullable=True)
    fine_range_low_eur = Column(Float, nullable=True)
    fine_range_high_eur = Column(Float, nullable=True)
    fine_estimate_eur = Column(Float, nullable=True)
    premium_range_low_eur = Column(Float, nullable=True)
    premium_range_high_eur = Column(Float, nullable=True)
    risk_tier = Column(String, nullable=True)  # "green"/"yellow"/"red"

    report_markdown = Column(Text, nullable=True)          # agent/underwriter report — internal, includes pricing
    client_report_markdown = Column(Text, nullable=True)   # client-facing report — remediation-focused, no pricing
    error_message = Column(Text, nullable=True)

    # Underwriter decision — the actual "policy issued" event. Nothing marked
    # this before; M3 (post-contract platform) provisioning has no trigger
    # without it.
    decision_status = Column(String, nullable=True, default="pending")  # pending/accepted/adjusted/rejected
    decision_premium_eur = Column(Float, nullable=True)   # final premium (may differ from the AI-suggested range)
    decision_notes = Column(Text, nullable=True)
    decided_by = Column(String, ForeignKey("agent_users.id"), nullable=True)
    decided_at = Column(DateTime, nullable=True)

    # M3 provisioning — set once the accepted decision has been handed off
    # to the post-contract platform (nis2.store). Kept minimal on purpose:
    # this is a status flag, not a queue — retries are manual for now.
    m3_provisioned = Column(String, nullable=False, default="no")  # "no"/"yes"/"failed"
    m3_provisioned_at = Column(DateTime, nullable=True)
    m3_provision_error = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    assessment = relationship("ClientAssessment", back_populates="scans")
