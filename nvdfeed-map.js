const fs = require('fs');
const assert = require('assert').strict;

function mapCveItem(item) {
  assert.strictEqual(item.cve.data_type, 'CVE');
  assert.strictEqual(item.cve.data_format, 'MITRE');
  assert.strictEqual(item.cve.data_version, '4.0');

  const id = item.cve.CVE_data_meta.ID;
  const published = Date.parse(item.publishedDate);
  const updated = Date.parse(item.lastModifiedDate);

  const description = mapCveDescription(item);
  const impact = mapCveImpact(item.impact);

  return { id, published, updated, description, ...impact };
}

function mapCveDescription(item) {
  for (data of item.cve.description.description_data) {
    if (data.lang === 'en') {
      return data.value;
    }
  }

  return item.cve.description.description_data[0].value;
}

function mapCveImpact(impact) {
  if (impact.baseMetricV3) {
    const metric = impact.baseMetricV3;
    return mapCveImpactMetricV3(metric);
  }

  if (impact.baseMetricV2) {
    const metric = impact.baseMetricV2;
    return mapCveImpactMetricV2(metric);
  }

  return { vector: null, score: null, severity: null };
}

function mapCveImpactMetricV3(metric) {
  const version = metric.cvssV3.version;
  assert(version === '3.0' || version === '3.1');

  const score = metric.cvssV3.baseScore;
  const vector = metric.cvssV3.vectorString;
  const severity = metric.cvssV3.baseSeverity;

  return { score, vector, severity };
}

function mapCveImpactMetricV2(metric) {
  assert.strictEqual(metric.cvssV2.version, '2.0');

  const score = metric.cvssV2.baseScore;
  const vector = metric.cvssV2.vectorString;
  const severity = metric.severity;

  return { score, vector, severity };
}

function isNotRejected(item) {
  return !item.description.startsWith('** REJECT **');
}

function compareByUpdatedTimestamp(item1, item2) {
  return item2.updated - item1.updated;
}

const inputFilePath = process.argv[2] || './nvdcve-1.1-modified.json';
const outputFilePath = process.argv[3] || './nvdcve-mapped.json';

const input = fs.readFileSync(inputFilePath);
const json = JSON.parse(input);

assert.strictEqual(json.CVE_data_type, 'CVE');
assert.strictEqual(json.CVE_data_version, '4.0');
const items = json.CVE_Items.map(mapCveItem).filter(isNotRejected);
items.sort(compareByUpdatedTimestamp);

const output = JSON.stringify(items, null, 2);
fs.writeFileSync(outputFilePath, output);
