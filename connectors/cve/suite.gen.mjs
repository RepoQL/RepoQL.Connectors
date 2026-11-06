// Writes the two suites of the CVE connector, suite.json for the import cve://recent and suite.kev.json for cve://kev:
//
//   node suite.gen.mjs && rql connector test <folder>/connector.ts --fixtures <folder>/suite.json
//
// Every CVE below is a real record, as NVD answered it on 2026-11-05 (fixtures/nvd.json), and every score a real EPSS
// score of that day (fixtures/epss.json). Three generations change a record the way NVD changes one: a numbering
// authority adds a score, a CVE is rejected, and a CVE arrives late. Those changes are made here, on copies of the real
// records, in the shape NVD gives a scored CVE and a rejected one. The model's answers are a person's reading of each
// CVE: its type, and whether its description says code runs or the attack comes over a network.
//
// What the model is asked is read from connector.ts itself, between its two markers, so a reworded question fails the
// suite until this file is run again.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const fixture = name => JSON.parse(readFileSync(new URL(`fixtures/${name}`, import.meta.url), 'utf8'));
const NVD_FIXTURE = fixture('nvd.json');
const EPSS_FIXTURE = fixture('epss.json');
const OSV_FIXTURE = fixture('osv.json');
const CWE_FIXTURE = fixture('cwe.json');
const PAGED = OSV_FIXTURE.paged;

const source = readFileSync(new URL('connector.ts', import.meta.url), 'utf8');
const literal = /\/\/ BEGIN QUESTIONS\r?\nconst QUESTIONS = ([\s\S]*?);\r?\n\/\/ END QUESTIONS/.exec(source);
if (!literal) throw new Error('connector.ts holds no QUESTIONS between its markers.');
const QUESTIONS = new Function(`return (${literal[1]});`)();
const TYPE_NAMES = Object.keys(QUESTIONS.type.criteria);

const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const EPSS = 'https://api.first.org/data/v1/epss';
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const CWE = 'https://cwe-api.mitre.org/api/v1/cwe';
const DAY_MS = 86400000;
const sha256 = text => createHash('sha256').update(text, 'utf8').digest('hex');
const iso = ms => new Date(ms).toISOString();
const utc = instant => /(Z|[+-]\d{2}:\d{2})$/.test(instant) ? instant : `${instant}Z`;

// ---------------------------------------------------------------------------------------------------------------------
// The records
// ---------------------------------------------------------------------------------------------------------------------

const real = id => structuredClone(NVD_FIXTURE.records[id]);
const BROTLI = real('CVE-2026-115946');      // a Perl package, no score yet
const DLINK = real('CVE-2026-120189');       // a router, the numbering authority's CVSS 4.0 9.3
const PLUGIN = real('CVE-2026-113482');      // a WordPress plugin, scored only by CISA
const LITELLM = real('CVE-2026-59822');      // an LLM gateway, known exploited
const SHAREPOINT = real('CVE-2026-56164');   // the numbering authority says 5.3, NVD 9.8, and known exploited
const REJECTED = real('CVE-2026-80726');     // withdrawn by its numbering authority
const LOGURU = real('CVE-2026-120217');      // arrives late, and the model cannot answer it
const LOG4J = real('CVE-2021-44228');        // published years before any window, and known exploited

// The numbering authority scores the Perl package: the shape of a CNA's CVSS 3.1 metric as NVD carries it.
const BROTLI_SCORED = structuredClone(BROTLI);
BROTLI_SCORED.cve.lastModified = '2026-11-05T09:12:44.103';
BROTLI_SCORED.cve.metrics = { cvssMetricV31: [{ source: BROTLI.cve.sourceIdentifier, type: 'Secondary', cvssData: {
  version: '3.1', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', baseScore: 8.8, baseSeverity: 'HIGH', attackVector: 'NETWORK',
  attackComplexity: 'LOW', privilegesRequired: 'NONE', userInteraction: 'REQUIRED', scope: 'UNCHANGED', confidentialityImpact: 'HIGH',
  integrityImpact: 'HIGH', availabilityImpact: 'HIGH' }, exploitabilityScore: 2.8, impactScore: 5.9 }] };

// The loguru CVE reaches NVD's modified listing late, as a CVE NVD receives after the last pass does.
const LOGURU_LATE = structuredClone(LOGURU);
LOGURU_LATE.cve.lastModified = '2026-11-05T15:02:10.880';

// The plugin's CVE is rejected: the shape of CVE-2026-80726, NVD's own rejected record.
const PLUGIN_REJECTED = { cve: { id: PLUGIN.cve.id, sourceIdentifier: PLUGIN.cve.sourceIdentifier, published: PLUGIN.cve.published,
  lastModified: '2026-11-05T11:40:02.517', vulnStatus: 'Rejected', cveTags: [],
  descriptions: [{ lang: 'en', value: 'Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.' }], metrics: {}, references: [] } };

// ---------------------------------------------------------------------------------------------------------------------
// The source
// ---------------------------------------------------------------------------------------------------------------------

// The windows connector.ts reads: from `from` up to 120 days at a time, until `now`.
function windows(from, now) {
  const out = [];
  for (let start = Date.parse(from); ;) {
    const end = Math.min(start + 120 * DAY_MS, Date.parse(now));
    out.push([iso(start), iso(end)]);
    if (end >= Date.parse(now)) return out;
    start = end;
  }
}

function page(records, timestamp) {
  return { resultsPerPage: records.length, startIndex: 0, totalResults: records.length, format: 'NVD_CVE', version: '2.0', timestamp, vulnerabilities: records };
}

const exploited = record => typeof record.cve.cisaExploitAdd === 'string';

// One request of NVD's listing for each window, answering the records published, or modified, in it. In cve://kev the
// connector asks for the known exploited alone, and NVD answers only those.
function listing(by, from, now, records, field, kev = false) {
  return windows(from, now).map(([start, end]) => ({
    method: 'GET', status: 200, headers: { 'content-type': 'application/json' },
    url: `${NVD}?${by}StartDate=${encodeURIComponent(start)}&${by}EndDate=${encodeURIComponent(end)}${kev ? '&hasKev' : ''}&resultsPerPage=200&startIndex=0`,
    json: page(records.filter(record => { const at = Date.parse(utc(record.cve[field])); return at >= Date.parse(start) && at <= Date.parse(end) && (!kev || exploited(record)); }), now.replace('Z', '')),
  }));
}

// NVD's listing of every CVE CISA lists as known exploited, whatever its age.
const knownExploited = (now, records) => ({
  method: 'GET', status: 200, headers: { 'content-type': 'application/json' },
  url: `${NVD}?hasKev&resultsPerPage=200&startIndex=0`, json: page(records.filter(exploited), now.replace('Z', '')),
});

// A full pass of cve://recent lists the window, then the known exploited.
const firstRead = (now, records, days = 365) => [...listing('pub', iso(Date.parse(now) - days * DAY_MS), now, records, 'published'), knownExploited(now, records)];
const changedSince = (watermark, now, records, kev = false) => listing('lastMod', watermark, now, records, 'lastModified', kev);
const newest = records => records.map(record => `${record.cve.lastModified}Z`).sort().at(-1);

// MITRE's CWE list as a pass reads it: the version, every category, the pillars of view 1000, each pillar's descendants,
// and the weaknesses in one batch. Every weakness the fixture CVEs name is in the tree, so no one is read alone.
const cweGet = (url, json) => ({ method: 'GET', url, status: 200, headers: { 'content-type': 'application/json' }, json });
const CWE_IDS = CWE_FIXTURE.weaknesses.map(weakness => Number(weakness.ID)).sort((a, b) => a - b);
const cweRead = [
  cweGet(`${CWE}/version`, CWE_FIXTURE.version),
  cweGet(`${CWE}/category/all`, CWE_FIXTURE.categories),
  cweGet(`${CWE}/view/1000`, CWE_FIXTURE.view),
  ...CWE_FIXTURE.view.Views[0].Members.map(member => cweGet(`${CWE}/${member.CweID}/descendants?view=1000`, CWE_FIXTURE.descendants[member.CweID])),
  cweGet(`${CWE}/weakness/${CWE_IDS.join(',')}`, { Weaknesses: CWE_FIXTURE.weaknesses }),
];
const CWE_ENTRIES = CWE_IDS.length + CWE_FIXTURE.categories.Categories.length;
// The same read, with MITRE having renamed one weakness, as it does between versions.
const cweReadRenaming = (id, name) => cweRead.map(interaction => interaction.url === `${CWE}/weakness/${CWE_IDS.join(',')}`
  ? { ...interaction, json: { Weaknesses: CWE_FIXTURE.weaknesses.map(weakness => weakness.ID === String(id) ? { ...weakness, Name: name } : weakness) } }
  : interaction);

const epssEnvelope = { status: 'OK', 'status-code': 200, version: '1.0', access: 'public' };
const SCORES = EPSS_FIXTURE.scores;
const epssPages = { method: 'GET', url: `${EPSS}?limit=10000&offset=0`, status: 200, json: { ...epssEnvelope, total: SCORES.length, offset: 0, limit: 10000, data: SCORES } };
const epssDay = { method: 'GET', url: `${EPSS}?limit=1&offset=0`, status: 200, json: { ...epssEnvelope, total: 400189, offset: 0, limit: 1, data: [SCORES[0]] } };

// ---------------------------------------------------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------------------------------------------------

const named = value => typeof value === 'string' && value.trim() !== '' && !/^(n\/a|na|-|\*|unknown|unspecified)$/i.test(value.trim()) ? value.trim() : undefined;

// What connector.ts shows the model about a record: the names its numbering authority states, and its description.
function state(record) {
  const cve = record.cve;
  const data = (cve.affected ?? []).filter(entry => entry.source === cve.sourceIdentifier).flatMap(entry => entry.affectedData ?? [])[0] ?? {};
  const description = cve.descriptions.find(text => text.lang === 'en').value;
  const out = { description: description.length > 6000 ? description.slice(0, 6000) : description };
  if (named(data.vendor)) out.vendor = named(data.vendor);
  if (named(data.product)) out.product = named(data.product);
  if (named(data.packageName)) out.package = named(data.packageName);
  return out;
}

const request = record => ({ state: state(record), questions: QUESTIONS });

// A person's reading of each CVE, which the suite records as the model's answer.
function reading(record, type, rce, network) {
  const probabilities = Object.fromEntries(TYPE_NAMES.map(name => [name, name === type ? 0.9 : Math.round(0.1 / (TYPE_NAMES.length - 1) * 10000) / 10000]));
  return { decide: request(record), answer: { model: 'decision-fixture', usage: { input_tokens: 1420, output_tokens: 9 }, answers: {
    type: { type: 'choice', choice: type, confidence: 0.8, probabilities },
    remote_code_execution: { type: 'noul', noul: rce },
    network_attack: { type: 'noul', noul: network },
  } } };
}

// ---------------------------------------------------------------------------------------------------------------------
// What the files must hold
// ---------------------------------------------------------------------------------------------------------------------

const BROTLI_UNSCORED = 'cves/2026-11/unscored/libraries/cpan.org/xs-libbrotli/CVE-2026-115946.rqlobject';
const BROTLI_HIGH = 'cves/2026-11/high/libraries/cpan.org/xs-libbrotli/CVE-2026-115946.rqlobject';
const DLINK_PATH = 'cves/2026-11/critical/devices/d-link/dir-505/CVE-2026-120189.rqlobject';
const PLUGIN_PATH = 'cves/2026-11/medium/cms/unknown/media-library-assistant/CVE-2026-113482.rqlobject';
const LITELLM_PATH = 'cves/2026-07/high/ai/berriai/litellm/CVE-2026-59822.rqlobject';
const SHAREPOINT_PATH = 'cves/2026-07/medium/apps/microsoft/microsoft-sharepoint-enterprise-server-2016/CVE-2026-56164.rqlobject';
const LOGURU_PATH = 'cves/2026-11/low/unclassified/delgan/loguru/CVE-2026-120217.rqlobject';
const LOG4J_PATH = 'cves/2021-12/critical/libraries/apache-software-foundation/apache-log4j2/CVE-2021-44228.rqlobject';
const origin = id => `https://www.cve.org/CVERecord?id=${id}`;

const G1 = '2026-11-05T06:00:00Z';
const WATERMARK = '2026-11-02T19:35:33.347Z';

const suite = {
  import: 'cve://recent',
  description: 'The CVE connector over NVD, as the import cve://recent: a first read of the year\'s window and of every known exploited CVE, in which the model reads every CVE and each is filed by month, severity and type; two hours with nothing new; a numbering authority scores a CVE, which moves it; a CVE is rejected, which moves it to rejected/; NVD fails, which removes nothing; a CVE the model cannot read yet arrives unclassified; cve_affects asks OSV about a package version, and follows OSV\'s page token; and a year later a full pass removes every CVE that left the window, but keeps the known exploited.',
  answers: [
    reading(BROTLI, 'libraries', 0.15, 0.35),
    reading(DLINK, 'devices', 0.42, 0.94),
    reading(PLUGIN, 'cms', 0.03, 0.35),
    reading(LITELLM, 'ai', 0.08, 0.96),
    reading(SHAREPOINT, 'apps', 0.05, 0.95),
    reading(LOG4J, 'libraries', 0.97, 0.96),
    { decide: request(LOGURU), answer: null },
  ],
  generations: [
    {
      name: 'the first read: every CVE published in the year arrives, and every known exploited one whatever its age; the model reads each, and each is filed by month, severity and type',
      clock: G1, pass: 'full',
      interactions: [...firstRead(G1, [BROTLI, DLINK, PLUGIN, LITELLM, SHAREPOINT, REJECTED, LOG4J]), ...cweRead, epssPages],
      expect: {
        collections: { cves: 7, epss: 6, labels: 6, placed: 7, weaknesses: CWE_ENTRIES },
        rows: { 'state/watermark': { value: { modified: WATERMARK } }, 'state/epss': { value: { date: '2026-11-04' } }, 'state/cwe': { value: { version: '4.21 of 2026-10-28', shape: 2 } } },
        paths: {
          [BROTLI_UNSCORED]: { origin: origin('CVE-2026-115946'), contains: ['"severity":"unscored"', '"type":"libraries"', 'pkg:cpan/XS-libbrotli'] },
          [DLINK_PATH]: { contains: ['"cvss_score":9.3', '"cvss_source":"cna"', '"type":"devices"', '"kind":"vulnerability.critical.devices"'] },
          [PLUGIN_PATH]: { contains: ['"cvss_source":"cisa"', '"severity":"medium"'] },
          [LITELLM_PATH]: { contains: ['"known_exploited":true', '"kev_added":"2026-09-02"', 'cve.known-exploited'] },
          [SHAREPOINT_PATH]: { contains: ['"cvss_score":5.3', '"cvss_source":"cna"', 'CVSS 3.1 9.8 from NVD'] },
          'rejected/CVE-2026-80726.rqlobject': { contains: ['cve.rejected', '"kind":"vulnerability.rejected"'] },
          'scores/epss.csv': { contains: ['cve,epss,percentile,date', 'CVE-2026-120189,0.01346,0.7151,2026-11-04'] },
          [LOG4J_PATH]: { origin: origin('CVE-2021-44228'), contains: ['"known_exploited":true', '"kev_added":"2021-12-10"', '"type":"libraries"', 'weaknesses/CWE-400.rqlobject', 'weaknesses/CWE-502.rqlobject'] },
          'overview.md': { contains: ['every CVE CISA lists as known exploited, whatever its age: 6 CVEs, and 1 withdrawn', '3 are known exploited'] },
          'weaknesses/CWE-1333.rqlobject': { origin: 'https://cwe.mitre.org/data/definitions/1333.html',
            contains: ['"kind":"weakness.base"', 'CWE-1333 — Inefficient Regular Expression Complexity', '"key":"child-of-407"', '"type":"EXTENDS"', 'weaknesses/CWE-407.rqlobject',
              '"structure":"CWE-1333 Inefficient Regular Expression Complexity, also called ReDoS, Regular Expression Denial of Service, Catastrophic backtracking\\nThe product uses a regular expression with a worst-case computational complexity that is inefficient and possibly exponential.\\nbase weakness · likelihood of exploit high · leads to DoS: Resource Consumption (CPU)\\nchild of CWE-407 Inefficient Algorithmic Complexity'] },
          'weaknesses/CWE-400.rqlobject': { contains: ['"kind":"weakness.class"', 'more specific weakness'] },
          'weaknesses/CWE-664.rqlobject': { contains: ['"kind":"weakness.pillar"'] },
          'weaknesses/CWE-264.rqlobject': { contains: ['"kind":"weakness.category"', 'CWE-264 Permissions, Privileges, and Access Controls', 'category of 0 weaknesses · obsolete'] },
          'weaknesses/README.md': { contains: ['# CWE weaknesses', 'content version 4.21 of 2026-10-28', 'Copyright © 2006–2026, The MITRE Corporation'] },
          'types/devices.md': { contains: ['1 CVEs, at `cves/*/*/devices/**`'] },
        },
        concepts: 3, terms: 16,
        views: {
          cve_vulnerabilities: { rows: 7, contains: [{ id: 'CVE-2026-120189', severity: 'critical', type: 'devices' }] },
          cve_known_exploited: { rows: 3, contains: [{ id: 'CVE-2026-59822' }, { id: 'CVE-2026-56164' }, { id: 'CVE-2021-44228' }] },
          cve_packages: { rows: 1, contains: [{ purl: 'pkg:cpan/XS-libbrotli' }] },
          cve_weaknesses: { rows: CWE_ENTRIES, contains: [{ id: 'CWE-400', abstraction: 'class', cves: 1 }, { id: 'CWE-306', cves: 2 }, { id: 'CWE-1333', abstraction: 'base', cves: 0 }] },
          'cve_recent(100000)': { rows: 6 },
        },
      },
    },
    {
      name: 'two hours later, nothing new: only the window since the watermark and the day of EPSS are asked, and every file is left alone',
      clock: '2026-11-05T08:00:00Z', pass: 'incremental',
      interactions: [...changedSince(WATERMARK, '2026-11-05T08:00:00Z', []), epssDay],
      expect: { written: 0, changed: 0, removed: 0 },
    },
    {
      name: 'the numbering authority scores the Perl package at 8.8: its file moves from unscored to high, and nothing else changes',
      clock: '2026-11-05T10:00:00Z', pass: 'incremental',
      interactions: [...changedSince(WATERMARK, '2026-11-05T10:00:00Z', [BROTLI_SCORED]), epssDay],
      expect: {
        rows: { 'state/watermark': { value: { modified: '2026-11-05T09:12:44.103Z' } } },
        paths: { [BROTLI_UNSCORED]: { absent: true }, [BROTLI_HIGH]: { contains: ['"severity":"high"', '"cvss_score":8.8', '"type":"libraries"', '"kind":"vulnerability.high.libraries"'] } },
      },
    },
    {
      name: 'the plugin\'s CVE is rejected: its file moves to rejected/, and it loses its reading',
      clock: '2026-11-05T12:00:00Z', pass: 'incremental',
      interactions: [...changedSince('2026-11-05T09:12:44.103Z', '2026-11-05T12:00:00Z', [PLUGIN_REJECTED]), epssDay],
      expect: {
        rows: { 'labels/CVE-2026-113482': { absent: true } },
        paths: { [PLUGIN_PATH]: { absent: true }, 'rejected/CVE-2026-113482.rqlobject': { contains: ['cve.rejected', 'rejected by its numbering authority'] } },
      },
    },
    {
      name: 'NVD fails with 503: the pass fails, and nothing is removed',
      clock: '2026-11-05T14:00:00Z', pass: 'incremental',
      interactions: [{ method: 'GET', status: 503, headers: { 'content-type': 'text/html' }, text: '<html><body>Service Unavailable</body></html>',
        url: changedSince('2026-11-05T11:40:02.517Z', '2026-11-05T14:00:00Z', [])[0].url }],
      expect: { failed: true, collections: { cves: 7 } },
    },
    {
      name: 'a CVE arrives that the model cannot read yet: it is filed as unclassified, and says so',
      clock: '2026-11-05T16:00:00Z', pass: 'incremental',
      interactions: [...changedSince('2026-11-05T11:40:02.517Z', '2026-11-05T16:00:00Z', [LOGURU_LATE]), epssDay],
      expect: {
        rows: { 'labels/CVE-2026-120217': { absent: true } },
        paths: { [LOGURU_PATH]: { contains: ['"type":"unclassified"', 'cve.unread', '"kind":"vulnerability.low.unclassified"', 'weaknesses/CWE-1333.rqlobject', 'weaknesses CWE-1333 Inefficient Regular Expression Complexity; CWE-400 Uncontrolled Resource Consumption'] } },
        views: { cve_weaknesses: { contains: [{ id: 'CWE-1333', cves: 1 }, { id: 'CWE-400', cves: 2 }] } },
      },
    },
    {
      name: 'cve_affects asks OSV which advisories name a package version, and an unnamed one has none',
      clock: '2026-11-05T17:30:00Z', pass: 'none',
      interactions: [{ method: 'POST', url: OSV_BATCH, status: 200,
        bodySha256: sha256(JSON.stringify({ queries: [{ package: { ecosystem: 'NuGet', name: 'Newtonsoft.Json' }, version: '12.0.1' }] })),
        json: { results: [OSV_FIXTURE.answer.results[0]] } }],
      expect: { views: { "cve_advisories('NuGet', 'Newtonsoft.Json', '12.0.1')": { rows: 1, contains: [{ advisory: 'GHSA-5crp-9r3c-p9vr' }] } } },
    },
    {
      name: 'OSV answers a page token: cve_affects follows it, and the advisories of the second page are in the answer',
      clock: '2026-11-05T17:45:00Z', pass: 'none',
      interactions: [
        { method: 'POST', url: OSV_BATCH, status: 200, bodySha256: sha256(JSON.stringify({ queries: [PAGED.query] })), json: { results: [PAGED.first] } },
        { method: 'POST', url: OSV_BATCH, status: 200, bodySha256: sha256(JSON.stringify({ queries: [{ ...PAGED.query, page_token: PAGED.first.next_page_token }] })), json: { results: [PAGED.second] } },
      ],
      expect: { views: { "cve_advisories('Debian:12', 'linux', '6.1.1-1')": { rows: 6, contains: [{ advisory: PAGED.second.vulns[0].id }, { advisory: PAGED.first.vulns[0].id }] } } },
    },
    {
      name: 'a year later, a full pass lists nothing published in the window: every CVE leaves, with its score, reading, place and file, but the known exploited, which stay whatever their age',
      clock: '2027-11-12T06:00:00Z', pass: 'full',
      interactions: [...firstRead('2027-11-12T06:00:00Z', [LITELLM, SHAREPOINT, LOG4J]), ...cweRead, epssPages],
      expect: {
        collections: { cves: 3, epss: 3, labels: 3, placed: 3, weaknesses: CWE_ENTRIES },
        paths: {
          [BROTLI_HIGH]: { absent: true }, [LOGURU_PATH]: { absent: true },
          'rejected/CVE-2026-80726.rqlobject': { absent: true }, 'rejected/CVE-2026-113482.rqlobject': { absent: true },
          [LITELLM_PATH]: { contains: ['"known_exploited":true'] }, [LOG4J_PATH]: { contains: ['"known_exploited":true'] },
          'overview.md': { contains: ['the CVEs published in the last 365 days, and every CVE CISA lists as known exploited, whatever its age: 3 CVEs'] },
        },
      },
    },
  ],
};

// The import cve://kev: only the known exploited, whatever their age, and every listing asks NVD for those alone.
const KEV_RECORDS = [LITELLM, SHAREPOINT, LOG4J];
const KEV_WATERMARK = newest(KEV_RECORDS);
const kevSuite = {
  import: 'cve://kev',
  description: 'The CVE connector over NVD, as the import cve://kev: a first read of every CVE CISA lists as known exploited, years old or new, and no other; two hours with nothing new, asked of NVD for the known exploited alone; and a week later a CVE NVD no longer lists as known exploited leaves.',
  answers: [reading(LITELLM, 'ai', 0.08, 0.96), reading(SHAREPOINT, 'apps', 0.05, 0.95), reading(LOG4J, 'libraries', 0.97, 0.96)],
  generations: [
    {
      name: 'the first read: every known exploited CVE arrives, whatever its age, and only those',
      clock: G1, pass: 'full',
      interactions: [knownExploited(G1, [BROTLI, DLINK, ...KEV_RECORDS]), ...cweRead, epssPages],
      expect: {
        collections: { cves: 3, epss: 3, labels: 3, placed: 3 },
        rows: { 'state/watermark': { value: { modified: KEV_WATERMARK } } },
        paths: {
          [LOG4J_PATH]: { origin: origin('CVE-2021-44228'), contains: ['"known_exploited":true', 'cve.known-exploited'] },
          'scores/epss.csv': { contains: ['CVE-2021-44228,0.99999,1,2026-11-04'] },
          [LITELLM_PATH]: { contains: ['"known_exploited":true'] }, [SHAREPOINT_PATH]: { contains: ['"known_exploited":true'] },
          'overview.md': { contains: ['# CVEs known to be exploited', 'This import holds the CVEs CISA lists as known exploited, whatever their age: 3 CVEs'] },
        },
        views: { cve_known_exploited: { rows: 3 } },
      },
    },
    {
      name: 'two hours later, nothing new: the modified window is asked for the known exploited alone, and every file is left alone',
      clock: '2026-11-05T08:00:00Z', pass: 'incremental',
      interactions: [...changedSince(KEV_WATERMARK, '2026-11-05T08:00:00Z', [], true), epssDay],
      expect: { written: 0, changed: 0, removed: 0 },
    },
    {
      name: 'a week later, NVD no longer lists the SharePoint CVE as known exploited, and MITRE renames CWE-306: the CVE leaves, and the LiteLLM CVE, unchanged itself, names CWE-306 by its new name',
      clock: '2026-11-12T06:00:00Z', pass: 'full',
      interactions: [knownExploited('2026-11-12T06:00:00Z', [LITELLM, LOG4J]), ...cweReadRenaming(306, 'Missing Authentication for a Critical Function'), epssPages],
      expect: {
        collections: { cves: 2, epss: 2, labels: 2, placed: 2 },
        paths: { [SHAREPOINT_PATH]: { absent: true }, [LOG4J_PATH]: { contains: ['"known_exploited":true'] },
          [LITELLM_PATH]: { contains: ['CWE-306 Missing Authentication for a Critical Function'] } },
      },
    },
    {
      name: 'a week on, MITRE answers a pillar\'s descendants with an empty object: the pass fails, and every weakness stays',
      clock: '2026-11-19T06:00:00Z', pass: 'full',
      interactions: [knownExploited('2026-11-19T06:00:00Z', [LITELLM, LOG4J]), ...cweRead.slice(0, 3),
        ...CWE_FIXTURE.view.Views[0].Members.map(member => cweGet(`${CWE}/${member.CweID}/descendants?view=1000`, {})),
        // Were the empty trees believed, every weakness the held CVEs name would be read alone, and MITRE has none.
        ...[20, 287, 306, 400, 502, 917].map(id => ({ method: 'GET', url: `${CWE}/weakness/${id}`, status: 404, headers: { 'content-type': 'application/json' }, json: `for weakness: cwe (${id}) not found` })),
        epssPages],
      expect: { failed: true, collections: { weaknesses: CWE_ENTRIES }, paths: { 'weaknesses/CWE-1333.rqlobject': { contains: ['"kind":"weakness.base"'] } } },
    },
  ],
};

writeFileSync(new URL('suite.json', import.meta.url), JSON.stringify(suite, null, 1) + '\n');
writeFileSync(new URL('suite.kev.json', import.meta.url), JSON.stringify(kevSuite, null, 1) + '\n');
