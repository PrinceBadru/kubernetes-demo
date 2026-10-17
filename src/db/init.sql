-- ==============================================================================
-- DevSecOps Demo: Initial Schema & Seed Data for Audit Records
-- ==============================================================================
-- Principle: Deterministic Demo Data & Parameterized Query Demonstration
-- Table: audit_logs
-- User: Restricted application user ('app')
-- ==============================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    action VARCHAR(64) NOT NULL,
    actor VARCHAR(64) NOT NULL,
    details TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Seed initial audit log records if table is empty
INSERT INTO audit_logs (action, actor, details)
SELECT 'USER_LOGIN', 'admin@demo.local', 'Successful authentication from trusted internal CIDR'
WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'USER_LOGIN');

INSERT INTO audit_logs (action, actor, details)
SELECT 'KEY_ROTATION', 'system', 'Automated service account token rotation completed'
WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'KEY_ROTATION');

INSERT INTO audit_logs (action, actor, details)
SELECT 'DEPLOYMENT', 'ci-runner', 'Version 1.0.0 deployed to devsecops-demo namespace'
WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'DEPLOYMENT');

INSERT INTO audit_logs (action, actor, details)
SELECT 'POLICY_AUDIT', 'security-scanner', 'Zero-trust network policies and Pod Security Admission validated'
WHERE NOT EXISTS (SELECT 1 FROM audit_logs WHERE action = 'POLICY_AUDIT');
