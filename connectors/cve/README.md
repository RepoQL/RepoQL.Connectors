# CVE connector

Copies the CVEs published in the last year, and every CVE known to be exploited, into RepoQL, beside the code they might affect. The CVEs come from NIST's National Vulnerability Database (NVD), and their exploit likelihood from FIRST's EPSS. A model reads what type of software each CVE concerns, and each CVE is filed by the month it was published, its severity, and that type. It is the starting point for CVE scanning with RepoQL: copy it, and change what your readers need.

## Two imports

| Import | What it holds | How big |
|--------|---------------|---------|
| `cve://recent` | Every CVE published in the window, exploited or not, and every CVE CISA lists as known exploited, whatever its age | About 210,000 CVEs for a year |
| `cve://kev` | Only the CVEs CISA lists as known exploited, whatever their age | About 1,800 CVEs |

Known exploited means CISA has evidence of exploitation in the wild, and that evidence can lag publication by days or weeks. Log4Shell, CVE-2021-44228, was listed on the day it was published. PHP's CVE-2026-109618 was published on 21 October 2026, and CISA listed it on 26 October, so for five days only `cve://recent` held it. Import `cve://kev` only if you act on confirmed exploitation alone. EPSS, in `scores/epss.csv`, estimates how likely a CVE is to be exploited before anyone has seen it happen.

The URI names what an import holds, not where it is read from. Both are read from NVD today, and a connector that reads another source keeps the same paths.

## Who it is for

Two jobs, both run by an agent over an uplink that holds the organization's code and this import side by side:

- **A nightly job.** It asks "are there new CVEs that affect us, and are they reachable?". The question starts as a glob, `cves/2026-11/critical/**`, or a query, `SELECT * FROM cve_recent(1)`. It ends as a question to the code: the agent reads the CVE's fixes and traces the vulnerable function through the code with `explore` and its references.
- **A review bot.** It checks a pull request's dependency changes against known advisories. `cve_affects` asks OSV about each changed package and version, live.

## The questions it answers

| Question | Read | Or query |
|----------|------|----------|
| What was reported this month? | `cves/2026-11/**` | `SELECT * FROM cve_recent(30)` |
| What is critical, and in what? | `cves/*/critical/**` | `SELECT id, type, vendor, product FROM cve_vulnerabilities WHERE severity = 'critical'` |
| What is in libraries, or in one vendor's software? | `cves/*/*/libraries/**`, `cves/*/*/*/apache/**` | `SELECT * FROM cve_vulnerabilities WHERE type = 'libraries'` |
| What is being exploited? | `overview.md` | `SELECT * FROM cve_known_exploited` |
| How likely is it to be exploited? | `scores/epss.csv` | `SELECT * FROM cve_epss('cve://recent/') WHERE cve = 'CVE-2026-59822'` |
| Which of our dependencies has an advisory? | | `SELECT * FROM cve_dependency_findings('file:///**')` |
| Does this package version have one? | | `SELECT cve_affects('NuGet', 'Newtonsoft.Json', '12.0.1')` |
| What does one CVE say, who scored it, what fixes it? | `cves/.../CVE-….rqlobject => structure` | `#symbol=score-1`, `#symbol=fix-1` |
| What kind of flaw is it, and what is it related to? | `weaknesses/CWE-1333.rqlobject => structure` | `SELECT * FROM cve_weaknesses ORDER BY cves DESC` |

`help/layout.md` says the same for an agent.

## What it reads, and what it sends

- **What it reads.**
  - NVD's CVE API, without a key: the CVEs published in the window and the known exploited, then every two hours those NVD modified since. It reads at most 9 requests a minute, under NVD's anonymous limit of 5 in 30 seconds. On 2026-11-05 a 30-day window held 17,425 CVEs, so a first read of a year is about 1,050 pages, which takes about two hours. `cve://kev` is about 9 pages.
  - EPSS's API: 10,000 scores to a page, once a day, when EPSS publishes the day's scores.
  - OSV's batch query, only when a query calls `cve_affects`. It sends the ecosystem, package names and versions the query passes it.
  - MITRE's CWE API, on a full pass and on the first pass: every weakness and category of the CWE list, in about 22 requests.
- **What it sends to the model.** For each CVE, once: the vendor, product and package names its numbering authority states, and its description, cut at 6,000 characters. Each request is charged to the plan of whoever installed the connector. A year is about 210,000 requests, which the 100,000 an import may have answered in a day spreads over three days. Until a CVE is read, it is filed under `unclassified`. `cve://kev` is about 1,800 requests.
- **What it writes.** Nothing anywhere: every request but OSV's is a GET, and OSV's batch query only reads.

## Weaknesses

Most CVEs name the weaknesses they are an instance of, such as CWE-79, cross-site scripting. The import holds MITRE's whole CWE list, each entry at `weaknesses/CWE-<id>.rqlobject`, and each CVE refers to the file of each weakness it names. The entries are linked to each other as the CWE list links them, in its Research Concepts view:

- **A weakness extends its parents.** CWE-1333, inefficient regular expressions, extends CWE-407. Each parent is a `child-of-<id>` node, with an `EXTENDS` relationship to the parent's file.
- **A weakness refers to its other relatives.** `can-precede-<id>`, `peer-of-<id>`, `can-also-be-<id>` and `requires-<id>` nodes each refer to the other weakness's file.
- **A category refers to its members.** Some CVEs name a category, such as CWE-264, in place of a weakness.
- **A weakness's structure names its relatives from both ends,** its children and what can precede it included.

Each entry's kind is its abstraction, `weakness.pillar`, `weakness.class`, `weakness.base`, `weakness.variant`, `weakness.compound` or `weakness.category`, so each has its own colour. `weaknesses/README.md` holds the CWE version and MITRE's copyright and license, which every copy of the CWE list must carry.

## How it decides

- **Severity** is the CVSS score of the first party in this order: the CVE's numbering authority, then CISA, then NVD, and CVSS 4.0 before 3.1 within each. The levels are none, low (to 3.9), medium (to 6.9), high (to 8.9), critical, and unscored when no party has scored it. NVD stopped scoring most CVEs in April 2026, so the numbering authority's own score usually decides. Every party's score is a node of the CVE, so a disagreement stays visible.
- **Type** is one of thirteen, each described in `connector.ts` with what it is not:

  | | | | |
  |---|---|---|---|
  | `libraries` | `frameworks` | `runtimes` | `databases` |
  | `servers` | `os` | `cloud` | `devtools` |
  | `apps` | `cms` | `devices` | `ai` |
  | `other` | | | |

  A model chose it, and a CVE no model has read is `unclassified`. The descriptions have not yet been checked against hand-labelled CVEs. Label 30 to 50 of your own, and read `rql connector test … --inference live --labels`, before you rely on them.
- **A CVE moves when its severity or type changes.** Its month never does. Link to a CVE by its origin, `https://www.cve.org/CVERecord?id=…`, which never moves.

## Why these sources

- **NVD's CVE API** holds every CVE, and lists them by the window they were published or modified in, 200 to a page. That fits a connector: a JSON response holds at most 4 MiB, and a connector cannot open the CVE List's zip archives.
- **CISA's known-exploited list** comes inside NVD's records, as `cisaExploitAdd`, so it needs no request of its own.
- **FIRST's EPSS** is the only public estimate of how likely a CVE is to be exploited.
- **OSV** matches a package and version to advisories, which NVD's product names cannot do reliably. It is asked live, only when a query calls `cve_affects`.
- **MITRE's CWE API** answers in JSON, where the CWE list's own download is a zip.

## Make it yours

This connector is meant to be copied and changed, by editing its code rather than by configuring it. The top of `connector.ts` holds the choices most copies change:

| Constant | Default | What it decides |
|----------|---------|-----------------|
| `WINDOW_DAYS` | 365 | How many days back `cve://recent` holds CVEs. It does not change `cve://kev` |
| `TYPES_WRITTEN` | every type | Which types of software are written as files, such as `new Set(['libraries', 'frameworks', 'runtimes'])`. The rest stay in the import's database |

The rest is written to be read and changed too. Change the questions the model is asked in `QUESTIONS`, how severity is chosen in `severityOf`, the path each CVE is filed at in `pathOf`, and what each CVE's object shows in `cveObject`. When you change what the model is asked or what a file holds, run `node suite.gen.mjs` and then the suites, as below.

Publish your copy under your own package id: change `package.id` in `manifest.yaml`, and raise `package.version` on every change.

## Test

```
node suite.gen.mjs
rql connector test connector.ts --fixtures suite.json
rql connector test connector.ts --fixtures suite.kev.json
```

Every recorded answer is real: the NVD, EPSS, OSV and CWE responses in `fixtures/` were captured on 2026-11-05.

## Install

From this repository's feed:

```
rql connector install RepoQL.Connectors.Cve --source https://repoql.github.io/RepoQL.Connectors/index.json
```

The install is a grant: four hosts, the model and the function. With no flags, rql shows what the connector asks for, on a page in your browser, and installs it on your answer. Then `rql import cve://recent`, or `rql import cve://kev`.
