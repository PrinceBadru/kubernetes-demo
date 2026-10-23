-- ==============================================================================
-- DevSecOps Demo: Initial Schema & Seed Data for Audit Records
-- ==============================================================================
-- Principle: Deterministic Demo Data & Concurrency-Safe Parameterized Query Demonstration
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

-- Seed initial audit log records deterministically with explicit IDs
-- ON CONFLICT (id) DO NOTHING guarantees concurrency safety during parallel pod starts
INSERT INTO audit_logs (id, action, actor, details)
VALUES 
  (1, 'USER_LOGIN', 'admin@demo.local', 'Successful authentication from trusted internal CIDR'),
  (2, 'KEY_ROTATION', 'system', 'Automated service account token rotation completed'),
  (3, 'DEPLOYMENT', 'ci-runner', 'Version 1.0.0 deployed to devsecops-demo namespace'),
  (4, 'POLICY_AUDIT', 'security-scanner', 'Zero-trust network policies and Pod Security Admission validated')
ON CONFLICT (id) DO NOTHING;

-- Synchronize sequence with highest existing ID
SELECT setval(pg_get_serial_sequence('audit_logs', 'id'), COALESCE((SELECT MAX(id) FROM audit_logs), 1));

-- ==============================================================================
-- Schema Migrations & Version Tracking (F-37 / F-66)
-- ==============================================================================
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT PRIMARY KEY,
    description VARCHAR(255) NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_migrations (version, description)
VALUES (1, 'Initial audit_logs schema with deterministic seed records')
ON CONFLICT (version) DO NOTHING;
