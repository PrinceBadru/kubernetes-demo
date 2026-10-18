import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

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

function validateDocument(catalog, sourceName, errors) {
  let checkedPaths = 0;
  const prefix = `[${sourceName}]`;

  if (!catalog) {
    errors.push(`${prefix} Document is empty or null`);
    return { checkedPaths: 0, ids: new Set() };
  }

  if (!catalog.version || !/^\d+\.\d+\.\d+$/.test(catalog.version)) {
    errors.push(`${prefix} Invalid or missing catalog version: ${catalog.version}`);
  }

  if (!catalog.description || typeof catalog.description !== 'string') {
    errors.push(`${prefix} Missing catalog description`);
  }

  if (!Array.isArray(catalog.scenarios) || catalog.scenarios.length === 0) {
    errors.push(`${prefix} Catalog must declare at least one scenario`);
  }

  const seenIds = new Set();

  for (const scn of catalog.scenarios || []) {
    const scnPrefix = `${prefix} [Scenario ${scn.id || 'UNKNOWN'}]`;

    if (!scn.id || !/^SCN-[A-Z0-9]+-\d{2}$/.test(scn.id)) {
      errors.push(`${scnPrefix} Invalid ID format (must match SCN-<CATEGORY>-XX)`);
    } else if (seenIds.has(scn.id)) {
      errors.push(`${scnPrefix} Duplicate scenario ID: ${scn.id}`);
    } else {
      seenIds.add(scn.id);
    }

    if (!scn.title || typeof scn.title !== 'string' || scn.title.length < 5) {
      errors.push(`${scnPrefix} Missing or too short title`);
    }

    if (!scn.category || !VALID_CATEGORIES.has(scn.category)) {
      errors.push(`${scnPrefix} Invalid category: ${scn.category}`);
    }

    if (!scn.learning_goal || typeof scn.learning_goal !== 'string') {
      errors.push(`${scnPrefix} Missing learning_goal`);
    }

    if (!scn.control_type || typeof scn.control_type !== 'string') {
      errors.push(`${scnPrefix} Missing control_type`);
    }

    if (!scn.prerequisites || typeof scn.prerequisites !== 'object') {
      errors.push(`${scnPrefix} Missing prerequisites object`);
    } else {
      if (typeof scn.prerequisites.cluster !== 'boolean') {
        errors.push(`${scnPrefix} prerequisites.cluster must be boolean`);
      }
      if (typeof scn.prerequisites.namespace !== 'string') {
        errors.push(`${scnPrefix} prerequisites.namespace must be string`);
      }
    }

    if (!scn.execution || typeof scn.execution !== 'object') {
      errors.push(`${scnPrefix} Missing execution object`);
    } else {
      if (!VALID_MODES.has(scn.execution.mode)) {
        errors.push(`${scnPrefix} Invalid execution.mode: ${scn.execution.mode}`);
      }
      if (!scn.execution.script || typeof scn.execution.script !== 'string') {
        errors.push(`${scnPrefix} Missing execution.script`);
      } else {
        const fullScript = path.join(rootDir, scn.execution.script);
        if (!fs.existsSync(fullScript)) {
          errors.push(`${scnPrefix} execution.script not found on disk: ${scn.execution.script}`);
        } else {
          checkedPaths++;
        }
      }
    }

    if (!scn.expected_state || !scn.expected_state.before || !scn.expected_state.after) {
      errors.push(`${scnPrefix} expected_state must include 'before' and 'after' descriptions`);
    }

    if (!scn.evidence || typeof scn.evidence !== 'object') {
      errors.push(`${scnPrefix} Missing evidence object`);
    }

    if (!scn.reversibility || !scn.reversibility.cleanup_action || !scn.reversibility.target) {
      errors.push(`${scnPrefix} reversibility must specify cleanup_action and target`);
    }

    if (scn.source_paths) {
      const manifests = scn.source_paths.manifests || [];
      const scripts = scn.source_paths.scripts || [];

      for (const manifestPath of manifests) {
        const fullManifest = path.join(rootDir, manifestPath);
        if (!fs.existsSync(fullManifest)) {
          errors.push(`${scnPrefix} Manifest path does not exist: ${manifestPath}`);
        } else {
          checkedPaths++;
        }
      }

      for (const scriptPath of scripts) {
        const fullScript = path.join(rootDir, scriptPath);
        if (!fs.existsSync(fullScript)) {
          errors.push(`${scnPrefix} Script path does not exist: ${scriptPath}`);
        } else {
          checkedPaths++;
        }
      }
    } else {
      errors.push(`${scnPrefix} Missing source_paths object`);
    }
  }

  return { checkedPaths, ids: seenIds };
}

function validate() {
  console.log('==============================================');
  console.log(' DevSecOps Scenario Catalog Validator');
  console.log('==============================================\n');

  const errors = [];

  if (!fs.existsSync(CATALOG_JSON)) {
    console.error(`FAIL: Catalog file not found at ${CATALOG_JSON}`);
    process.exit(1);
  }

  if (!fs.existsSync(CATALOG_YAML)) {
    errors.push(`YAML catalog missing at ${CATALOG_YAML}`);
  }

  if (!fs.existsSync(SCHEMA_FILE)) {
    errors.push(`Schema file missing: ${SCHEMA_FILE}`);
  }

  let catalogJson;
  try {
    const raw = fs.readFileSync(CATALOG_JSON, 'utf-8');
    catalogJson = JSON.parse(raw);
  } catch (err) {
    errors.push(`Could not parse catalog JSON: ${err.message}`);
  }

  let catalogYaml;
  if (fs.existsSync(CATALOG_YAML)) {
    try {
      const raw = fs.readFileSync(CATALOG_YAML, 'utf-8');
      catalogYaml = YAML.parse(raw);
    } catch (err) {
      errors.push(`Could not parse catalog YAML: ${err.message}`);
    }
  }

  const jsonResult = catalogJson
    ? validateDocument(catalogJson, 'catalog.json', errors)
    : { checkedPaths: 0, ids: new Set() };
  const yamlResult = catalogYaml
    ? validateDocument(catalogYaml, 'catalog.yaml', errors)
    : { checkedPaths: 0, ids: new Set() };

  // Verify parity between catalog.json and catalog.yaml
  if (catalogJson && catalogYaml) {
    const jsonOnly = [...jsonResult.ids].filter((id) => !yamlResult.ids.has(id));
    const yamlOnly = [...yamlResult.ids].filter((id) => !jsonResult.ids.has(id));

    if (jsonOnly.length > 0) {
      errors.push(
        `Scenario(s) present in catalog.json but missing in catalog.yaml: ${jsonOnly.join(', ')}`,
      );
    }
    if (yamlOnly.length > 0) {
      errors.push(
        `Scenario(s) present in catalog.yaml but missing in catalog.json: ${yamlOnly.join(', ')}`,
      );
    }
  }

  if (errors.length > 0) {
    console.error(`Validation failed with ${errors.length} error(s):\n`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  console.log(`JSON Catalog:       ${CATALOG_JSON}`);
  console.log(`YAML Catalog:       ${CATALOG_YAML}`);
  console.log(`Catalog Version:    ${catalogJson.version}`);
  console.log(`Total Scenarios:    ${jsonResult.ids.size} (JSON) / ${yamlResult.ids.size} (YAML)`);
  console.log(`Source Paths Check: ${jsonResult.checkedPaths} referenced files verified on disk`);
  console.log('\nResult: ALL SCENARIOS VALID, SYNCHRONIZED, AND SOURCE PATHS RESOLVED.');
}

validate();
