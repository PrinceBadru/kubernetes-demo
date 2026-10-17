import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const CATALOG_JSON = path.join(rootDir, 'docs', 'scenarios', 'catalog.json');
const CATALOG_YAML = path.join(rootDir, 'docs', 'scenarios', 'catalog.yaml');
const SCHEMA_FILE = path.join(rootDir, 'docs', 'scenarios', 'schema.json');

const VALID_CATEGORIES = new Set([
  'workload-management',
  'network-security',
  'container-hardening',
  'access-control',
  'application-security',
  'reliability',
  'resilience',
  'observability',
]);

const VALID_MODES = new Set(['live', 'simulated', 'declarative']);

function validate() {
  console.log('==============================================');
  console.log(' DevSecOps Scenario Catalog Validator');
  console.log('==============================================\n');

  const errors = [];
  let checkedPaths = 0;

  if (!fs.existsSync(CATALOG_JSON)) {
    console.error(`FAIL: Catalog file not found at ${CATALOG_JSON}`);
    process.exit(1);
  }

  if (!fs.existsSync(CATALOG_YAML)) {
    console.warn(`WARN: YAML catalog missing at ${CATALOG_YAML}`);
  }

  if (!fs.existsSync(SCHEMA_FILE)) {
    errors.push(`Schema file missing: ${SCHEMA_FILE}`);
  }

  let catalog;
  try {
    const raw = fs.readFileSync(CATALOG_JSON, 'utf-8');
    catalog = JSON.parse(raw);
  } catch (err) {
    console.error(`FAIL: Could not parse catalog JSON: ${err.message}`);
    process.exit(1);
  }

  if (!catalog.version || !/^\d+\.\d+\.\d+$/.test(catalog.version)) {
    errors.push(`Invalid or missing catalog version: ${catalog.version}`);
  }

  if (!catalog.description || typeof catalog.description !== 'string') {
    errors.push('Missing catalog description');
  }

  if (!Array.isArray(catalog.scenarios) || catalog.scenarios.length === 0) {
    errors.push('Catalog must declare at least one scenario');
  }

  const seenIds = new Set();

  for (const scn of catalog.scenarios || []) {
    const prefix = `[Scenario ${scn.id || 'UNKNOWN'}]`;

    if (!scn.id || !/^SCN-[A-Z0-9]+-\d{2}$/.test(scn.id)) {
      errors.push(`${prefix} Invalid ID format (must match SCN-<CATEGORY>-XX)`);
    } else if (seenIds.has(scn.id)) {
      errors.push(`${prefix} Duplicate scenario ID: ${scn.id}`);
    } else {
      seenIds.add(scn.id);
    }

    if (!scn.title || typeof scn.title !== 'string' || scn.title.length < 5) {
      errors.push(`${prefix} Missing or too short title`);
    }

    if (!scn.category || !VALID_CATEGORIES.has(scn.category)) {
      errors.push(`${prefix} Invalid category: ${scn.category}`);
    }

    if (!scn.learning_goal || typeof scn.learning_goal !== 'string') {
      errors.push(`${prefix} Missing learning_goal`);
    }

    if (!scn.control_type || typeof scn.control_type !== 'string') {
      errors.push(`${prefix} Missing control_type`);
    }

    if (!scn.prerequisites || typeof scn.prerequisites !== 'object') {
      errors.push(`${prefix} Missing prerequisites object`);
    }

    if (!scn.execution || typeof scn.execution !== 'object') {
      errors.push(`${prefix} Missing execution object`);
    } else {
      if (!VALID_MODES.has(scn.execution.mode)) {
        errors.push(`${prefix} Invalid execution.mode: ${scn.execution.mode}`);
      }
      if (scn.execution.script) {
        const fullScript = path.join(rootDir, scn.execution.script);
        if (!fs.existsSync(fullScript)) {
          errors.push(`${prefix} execution.script not found on disk: ${scn.execution.script}`);
        } else {
          checkedPaths++;
        }
      }
    }

    if (!scn.expected_state || !scn.expected_state.before || !scn.expected_state.after) {
      errors.push(`${prefix} expected_state must include 'before' and 'after' descriptions`);
    }

    if (!scn.evidence || typeof scn.evidence !== 'object') {
      errors.push(`${prefix} Missing evidence object`);
    }

    if (!scn.reversibility || !scn.reversibility.cleanup_action || !scn.reversibility.target) {
      errors.push(`${prefix} reversibility must specify cleanup_action and target`);
    }

    if (scn.source_paths) {
      const manifests = scn.source_paths.manifests || [];
      const scripts = scn.source_paths.scripts || [];

      for (const manifestPath of manifests) {
        const fullManifest = path.join(rootDir, manifestPath);
        if (!fs.existsSync(fullManifest)) {
          errors.push(`${prefix} Manifest path does not exist: ${manifestPath}`);
        } else {
          checkedPaths++;
        }
      }

      for (const scriptPath of scripts) {
        const fullScript = path.join(rootDir, scriptPath);
        if (!fs.existsSync(fullScript)) {
          errors.push(`${prefix} Script path does not exist: ${scriptPath}`);
        } else {
          checkedPaths++;
        }
      }
    } else {
      errors.push(`${prefix} Missing source_paths object`);
    }
  }

  if (errors.length > 0) {
    console.error(`Validation failed with ${errors.length} error(s):\n`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log(`Catalog Version:    ${catalog.version}`);
  console.log(`Total Scenarios:    ${seenIds.size}`);
  console.log(`Source Paths Check: ${checkedPaths} referenced files verified on disk`);
  console.log('\nResult: ALL SCENARIOS VALID AND SOURCE PATHS RESOLVED.');
}

validate();
