import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv from 'ajv';
import YAML from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

const CATALOG_JSON = path.join(rootDir, 'docs', 'scenarios', 'catalog.json');
const CATALOG_YAML = path.join(rootDir, 'docs', 'scenarios', 'catalog.yaml');
const SCHEMA_FILE = path.join(rootDir, 'docs', 'scenarios', 'schema.json');

function deepEqual(a, b, pathStr = '') {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null || typeof a !== 'object') return a === b;

  if (Array.isArray(a) !== Array.isArray(b)) return false;

  if (Array.isArray(a)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!deepEqual(a[i], b[i], `${pathStr}[${i}]`)) return false;
    }
    return true;
  }

  const keysA = Object.keys(a)
    .filter((k) => k !== '$schema' && k !== 'schema')
    .sort();
  const keysB = Object.keys(b)
    .filter((k) => k !== '$schema' && k !== 'schema')
    .sort();

  if (keysA.length !== keysB.length) return false;
  for (let i = 0; i < keysA.length; i++) {
    if (keysA[i] !== keysB[i]) return false;
    if (!deepEqual(a[keysA[i]], b[keysB[i]], `${pathStr}.${keysA[i]}`)) return false;
  }
  return true;
}

function validateFilePaths(catalog, sourceName, errors) {
  let checkedPaths = 0;
  const prefix = `[${sourceName}]`;

  for (const scn of catalog.scenarios || []) {
    const scnPrefix = `${prefix} [Scenario ${scn.id || 'UNKNOWN'}]`;

    if (scn.execution && scn.execution.script) {
      const fullScript = path.join(rootDir, scn.execution.script);
      if (!fs.existsSync(fullScript)) {
        errors.push(`${scnPrefix} execution.script not found on disk: ${scn.execution.script}`);
      } else {
        checkedPaths++;
      }
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
    }
  }

  return checkedPaths;
}

function checkCanonicalParity(jsonDoc, yamlDoc, errors) {
  if (jsonDoc.version !== yamlDoc.version) {
    errors.push(
      `Parity error: catalog version mismatch (JSON: "${jsonDoc.version}", YAML: "${yamlDoc.version}")`,
    );
  }
  if (jsonDoc.description !== yamlDoc.description) {
    errors.push(`Parity error: catalog description mismatch between JSON and YAML`);
  }

  const jsonScenarios = jsonDoc.scenarios || [];
  const yamlScenarios = yamlDoc.scenarios || [];

  if (jsonScenarios.length !== yamlScenarios.length) {
    errors.push(
      `Parity error: scenario count mismatch (JSON: ${jsonScenarios.length}, YAML: ${yamlScenarios.length})`,
    );
    return;
  }

  for (let i = 0; i < jsonScenarios.length; i++) {
    const sJ = jsonScenarios[i];
    const sY = yamlScenarios.find((s) => s.id === sJ.id);
    if (!sY) {
      errors.push(
        `Parity error: scenario ${sJ.id} found in catalog.json but missing in catalog.yaml`,
      );
      continue;
    }

    if (!deepEqual(sJ, sY, sJ.id)) {
      errors.push(
        `Parity error: scenario content mismatch for ${sJ.id}:\n` +
          `  JSON: ${JSON.stringify(sJ)}\n` +
          `  YAML: ${JSON.stringify(sY)}`,
      );
    }
  }
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

  let schema;
  let ajvValidate;
  if (fs.existsSync(SCHEMA_FILE)) {
    try {
      const raw = fs.readFileSync(SCHEMA_FILE, 'utf-8');
      schema = JSON.parse(raw);
      const ajv = new Ajv({ allErrors: true, strict: false });
      ajvValidate = ajv.compile(schema);
    } catch (err) {
      errors.push(`Failed to compile schema: ${err.message}`);
    }
  }

  // 1. JSON Schema validation via Ajv
  if (ajvValidate && catalogJson) {
    const validJson = ajvValidate(catalogJson);
    if (!validJson) {
      for (const err of ajvValidate.errors || []) {
        errors.push(`[catalog.json Schema] ${err.instancePath || '/'} ${err.message}`);
      }
    }
  }

  if (ajvValidate && catalogYaml) {
    const validYaml = ajvValidate(catalogYaml);
    if (!validYaml) {
      for (const err of ajvValidate.errors || []) {
        errors.push(`[catalog.yaml Schema] ${err.instancePath || '/'} ${err.message}`);
      }
    }
  }

  // 2. Deep canonical parity check
  if (catalogJson && catalogYaml) {
    checkCanonicalParity(catalogJson, catalogYaml, errors);
  }

  // 3. Referenced source paths resolution check
  const jsonPathsCount = catalogJson ? validateFilePaths(catalogJson, 'catalog.json', errors) : 0;
  if (catalogYaml) {
    validateFilePaths(catalogYaml, 'catalog.yaml', errors);
  }

  if (errors.length > 0) {
    console.error(`Validation failed with ${errors.length} error(s):\n`);
    for (const err of errors) {
      console.error(`  - ${err}`);
    }
    process.exit(1);
  }

  const scenarioCount = catalogJson.scenarios ? catalogJson.scenarios.length : 0;
  console.log(`JSON Catalog:          ${CATALOG_JSON}`);
  console.log(`YAML Catalog:          ${CATALOG_YAML}`);
  console.log(`Schema File:           ${SCHEMA_FILE} (Ajv Draft-07 compiled)`);
  console.log(`Catalog Version:       ${catalogJson.version}`);
  console.log(
    `Total Scenarios:       ${scenarioCount} (JSON) / ${catalogYaml.scenarios.length} (YAML)`,
  );
  console.log(`Canonical Parity:      VERIFIED (100% deep field match)`);
  console.log(`Source Paths Check:    ${jsonPathsCount} referenced files verified on disk`);
  console.log('\nResult: ALL SCENARIOS VALID, SYNCHRONIZED, AND SOURCE PATHS RESOLVED.');
}

validate();
