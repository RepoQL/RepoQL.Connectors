# CVE connector

Copies the CVEs published in the last 30 days, and every CVE known to be exploited, into RepoQL, beside the code they might affect. The CVEs come from NIST's National Vulnerability Database (NVD), and their exploit likelihood from FIRST's EPSS. Rules read what type of software each CVE concerns, asking a model only about the CVEs they do not recognise, and each CVE is filed by the month it was published, its severity, and that type. It is the starting point for CVE scanning with RepoQL: copy it, and change what your readers need.

## Two imports

| Import | What it holds | How big |
|--------|---------------|---------|
| `cve://recent` | Every CVE published in the window, exploited or not, and every CVE CISA lists as known exploited, whatever its age | About 17,000 CVEs for the default 30 days, and 210,000 for a year |
| `cve://kev` | Only the CVEs CISA lists as known exploited, whatever their age | About 1,800 CVEs |

The window is measured when a full pass runs, once a week. Between full passes each new CVE is added and none leaves, so `cve://recent` holds from 30 to 37 days: an import whose last full pass was six days ago holds 36.

Known exploited means CISA has evidence of exploitation in the wild, and that evidence can lag publication by days or weeks. Log4Shell, CVE-2021-44228, was listed on the day it was published. PHP's CVE-2026-109618 was published on 21 October 2026, and CISA listed it on 26 October, so for five days only `cve://recent` held it. Import `cve://kev` only if you act on confirmed exploitation alone. EPSS, in `scores/epss.csv`, estimates how likely a CVE is to be exploited before anyone has seen it happen.

The URI names what an import holds, not where it is read from. Both are read from NVD today, and a connector that reads another source keeps the same paths.

## Who it is for

Two jobs, both run by an agent over an uplink that holds the organization's code and this import side by side:

- **A nightly job.** It asks "are there new CVEs that affect us, and are they reachable?". The question starts as a glob, `cves/2026-11/critical/**`, or a query, `SELECT * FROM cve_recent(1)`. It ends as a question to the code: the agent reads the CVE's fixes and traces the vulnerable function through the code with `explore` and its references.
- **A review bot.** It checks a pull request's dependency changes against known advisories. `cve_dependency_findings` asks OSV about every dependency the changed manifests and lock files hold, live, and `cve_affects` about one package and version.

## The questions it answers

| Question | Read | Or query |
|----------|------|----------|
| What was published this month? | `cves/2026-11/**` | `SELECT * FROM cve_vulnerabilities WHERE month = '2026-11'` |
| How many were published on each of the last few days? | `overview.md`, for the last 7 | `SELECT CAST(published AS DATE) AS day, count(*) FROM cve_vulnerabilities WHERE published >= CAST(now() AT TIME ZONE 'UTC' AS DATE) - INTERVAL 2 DAY GROUP BY day` |
| Which CVEs name this product, whichever product the path names? | | `SELECT DISTINCT id, severity FROM cve_products WHERE product ILIKE '%Windows Server 2019%'` |
| Which versions does it affect, and where does the range end? | the CVE's `product-<n>` nodes | `SELECT product, range, first_unaffected FROM cve_products WHERE id = 'CVE-2021-44228'` |
| Is this version in a CVE's affected range? | | `SELECT id, range, in_range FROM cve_in_range('Windows Server 2019', '10.0.17763.9000') WHERE in_range <> 'no'` |
| What is critical, and in what? | `cves/*/critical/**` | `SELECT id, type, vendor, product FROM cve_vulnerabilities WHERE severity = 'critical'` |
| What is in libraries, or in one vendor's software? | `cves/*/*/libraries/**`, `cves/*/*/*/apache/**` | `SELECT * FROM cve_vulnerabilities WHERE type = 'libraries'` |
| What is being exploited? | `overview.md` | `SELECT * FROM cve_known_exploited` |
| Which have a public exploit, though nobody is seen using it yet? | | `SELECT id, vendor, product FROM cve_vulnerabilities WHERE exploitation = 'poc' AND automatable = 'yes'` |
| How likely is it to be exploited? | `scores/epss.csv` | `SELECT * FROM cve_epss('cve://recent/') WHERE cve = 'CVE-2026-59822'` |
| Which of our dependencies has an advisory? | | `SELECT * FROM cve_dependency_findings('file:///**')` |
| Which dependencies were not checked, and why? | | `SELECT * FROM cve_dependency_unchecked('file:///**')` |
| Does this package version have one? | | `SELECT cve_affects('NuGet', 'Newtonsoft.Json', '12.0.1')` |
| What does one CVE say, who scored it, what fixes it? | `cves/.../CVE-….rqlobject => structure` | `#symbol=score-1`, `#symbol=fix-1` |
| What kind of flaw is it, and what is it related to? | `weaknesses/CWE-1333.rqlobject => structure` | `SELECT * FROM cve_weaknesses ORDER BY cves DESC` |

`help/layout.md` says the same for an agent.

## What it reads, and what it sends

- **What it reads.**
  - NVD's CVE API, without a key: the CVEs published in the window and the known exploited, then every two hours those NVD modified since. It reads at most 9 requests a minute, under NVD's anonymous limit of 5 in 30 seconds. On 2026-11-05 the 30-day window held 17,425 CVEs, so a first read is about 90 pages, which takes about ten minutes. A year is about 1,050 pages, about two hours. `cve://kev` is about 9 pages.
  - EPSS's API: 10,000 scores to a page, once a day, when EPSS publishes the day's scores.
  - OSV's batch query, only when a query calls `cve_affects`. It sends the ecosystem, package names and versions the query passes it. `cve_dependency_findings` passes it the workspace's dependencies, and only those whose address names the ecosystem's public registry. For npm, Python, Cargo, Bundler and Composer that keeps a private registry's package from being sent. For NuGet, Maven and Go it cannot, as [Dependencies](#dependencies) says. `cve_dependency_questions` lists what would be sent, and sends nothing.
  - MITRE's CWE API, on a full pass and on the first pass: every weakness and category of the CWE list, in about 22 requests.
- **What it sends to the model.** Only for a CVE the rules cannot place, about 29% of them, once: the vendor, product and package names its numbering authority states, and its description, cut at 6,000 characters, with one question, its type. Each request is charged to the plan of whoever installed the connector. For the default 30 days that is about 5,000 requests, and a year about 60,000, both inside the 100,000 an import may have answered in a day. Until a CVE is placed, it is filed under `unclassified`. `cve://kev` is a few hundred.
- **What it writes.** Nothing anywhere: every request but OSV's is a GET, and OSV's batch query only reads.

## Dependencies

`cve_dependency_findings(files)` reads RepoQL's `dependencies` view, so it covers every ecosystem that view reads and OSV names: npm, Yarn, pnpm and Bun; NuGet; Maven and Gradle; Go; Python; Cargo; Bundler; and Composer. It reads a lock file's own entries too, so a vulnerable package nothing in the manifest names is found. It needs rql 1.7.23 or later, the first release whose `dependencies` view states each usage's `pin`.

| `dependencies` ecosystem | OSV's name | The public registry its address must name |
|--------------------------|------------|-------------------------------------------|
| `npm` | `npm` | `npm://registry.npmjs.org/` |
| `nuget` | `NuGet` | `nuget://nuget.org/` |
| `maven` | `Maven` | `maven://repo.maven.apache.org/` |
| `golang` | `Go` | `go://proxy.golang.org/` |
| `pypi` | `PyPI` | `python://pypi.org/` |
| `cargo` | `crates.io` | `rust://crates.io/` |
| `gem` | `RubyGems` | `ruby-gem://rubygems.org/` |
| `composer` | `Packagist` | `composer://repo.packagist.org/` |

The table is `sql/osv_question.sql`, and a new ecosystem is one line there.

- **A package is matched by its registry address, not by its name alone.** OSV knows the public registries. A package a private registry serves is another package than the public one of that name, so it is not asked, and its name is not sent. RepoQL writes every NuGet, Maven and Go package at its public address, whatever feed, repository or proxy serves it, so for those three the files cannot tell a private package from a public one: its name and version are sent, as they were before this macro read other ecosystems. `cve_dependency_questions` shows each one first.
- **A dependency that was not asked is listed, not dropped.** `cve_dependency_unchecked(files)` has a row for each, with the reason: `no-version` when no file settles a version, `not-the-public-registry`, or `no-osv-ecosystem`, as for a container image. No finding means nothing was found among the dependencies that were asked. Read both before calling anything clean.
- **The version asked is the version in effect, where a file settles one**: a lock file's entry, a version a parent POM manages, or an exact requirement. A Go `require` and a NuGet `1.2.3` are minimums, so they are asked at that version, and the row's `pin` says `minimum`: the build may hold a later one. A requirement under NuGet's central package management is asked at the version its `Directory.Packages.props` sets.
- **A component a package embeds is not a dependency.** A native library or a runtime inside a package is found only by searching the CVEs' products and descriptions.

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

  Rules choose it, in this order: the numbering authority, when it publishes one type of software (the Linux kernel's, Chrome's, and WordPress's); the vendor and product names it gives; the description; and the package's ecosystem. A model chooses it only for a CVE no rule recognises, and `type_rule` says which decided: `name:os`, `assigner:cms`, `package`, or `model`. Measured on 19,516 CVEs a model had read, the rules placed 71% of them, and agreed with the model on 85% of those. Neither has been checked against CVEs labelled by hand: label 30 to 50 of your own before you rely on either. A CVE neither can place is `unclassified`.
- **A CVE's products** are the ones its numbering authority says are affected. A record also lists products to say they are unaffected, or that nobody knows yet, and those are left out. Each product is a node of the CVE, and `cve_products` has a row for each product and range. The path, and `vendor` and `product`, name only the first: a Windows flaw lists every Windows release and is filed under the first.
- **A range of versions** is kept as the bounds the record states and written as comparisons, such as `>= 2.0, < 2.17.1`. `first_unaffected` is where the record says the range ends, which is not a confirmed fix. The bounds are text. `cve_version_key` turns a version written as numbers joined by dots into a key that compares in version order, and `cve_in_range(product, version)` answers `yes`, `no` or `cannot tell` for each range with it. Of 4,692 affected ranges in 1,500 CVEs published from 20 October to 10 November 2026, 65% had bounds it can compare; the rest carry a suffix (18%), are git commits (11%), or are prose or a package release (6%), and for those it answers `cannot tell` and never guesses. A file keeps 25 products and 20 ranges of each, and says so when a record states more.
- **Attack vector** is the scorer's CVSS vector: `network`, `adjacent`, `local` or `physical`. A CVE nobody has scored has none.
- **Code execution** is true when the description says an attacker runs code or commands, or when the CVE names a weakness that is code execution by definition, such as CWE-78, OS command injection.
- **A CVE moves when its severity or type changes.** Its month never does. Link to a CVE by its origin, `https://www.cve.org/CVERecord?id=…`, which never moves.

## Why these sources

- **NVD's CVE API** holds every CVE, and lists them by the window they were published or modified in, 200 to a page. That fits a connector: a JSON response holds at most 4 MiB, and a connector cannot open the CVE List's zip archives.
- **CISA's known-exploited list** comes inside NVD's records, as `cisaExploitAdd`, so it needs no request of its own. So does **CISA's SSVC decision**, which says whether an exploit is public, among the metrics as `ssvcV203`.
- **NVD's CPE configurations** name the products of a record whose numbering authority named none, as most from before 2016 do. NVD alone holds them: the CVE List itself names no product for such a record.
- **Not the public GitHub mirrors.** The CVE List (`CVEProject/cvelistV5`) is authoritative and current within minutes, but holds no CPEs, its change log is a single file of 37 MB, and its archive a zip. CISA's `vulnrichment` and the GitHub Advisory Database add nothing NVD's records and OSV do not already carry.
- **FIRST's EPSS** is the only public estimate of how likely a CVE is to be exploited.
- **OSV** matches a package and version to advisories, which NVD's product names cannot do reliably. It is asked live, only when a query calls `cve_affects`.
- **MITRE's CWE API** answers in JSON, where the CWE list's own download is a zip.

## Make it yours

This connector is meant to be copied and changed, by editing its code rather than by configuring it. The top of `connector.ts` holds the choices most copies change:

| Constant | Default | What it decides |
|----------|---------|-----------------|
| `WINDOW_DAYS` | 30 | How many days back `cve://recent` holds CVEs. It does not change `cve://kev` |
| `TYPES_WRITTEN` | every type | Which types of software are written as files, such as `new Set(['libraries', 'frameworks', 'runtimes'])`. The rest stay in the import's database |

The rest is written to be read and changed too. Change the rules that read each CVE between `BEGIN RULES` and `END RULES`, the question the model is asked about the rest in `QUESTIONS`, how severity is chosen in `severityOf`, the path each CVE is filed at in `pathOf`, and what each CVE's object shows in `cveObject`. When you change what the model is asked or what a file holds, run `node suite.gen.mjs` and then the suites, as below.

Publish your copy under your own package id: change `package.id` in `manifest.yaml`, and raise `package.version` on every change.

## Test

```
node suite.gen.mjs
rql connector test connector.ts --fixtures suite.json
rql connector test connector.ts --fixtures suite.kev.json
```

Until rql reads the manifest's `package` block, run the suites on a staged copy: see [the repository's README](../../README.md#until-rql-reads-the-package-block).

Every recorded answer is real: the NVD, EPSS, OSV and CWE responses in `fixtures/` were captured on 2026-11-05, and a few records since, as each fixture file says. Each of the eight dependency rows in `fixtures/osv.json` is read from a real file of a public repository, which its `from` names, with what OSV answered for it on 2026-11-18.

A suite cannot hold a workspace's manifests and lock files, so it proves what is asked for one row of `dependencies`, through `cve_dependency_check`, and not the read of the view itself. Prove that on a host: `SELECT * FROM cve_dependency_questions('file:///**')` sends nothing.

## Install

From this repository's feed:

```
rql connector install RepoQL.Connectors.Cve --source https://repoql.github.io/RepoQL.Connectors/index.json
```

The install is a grant: four hosts, the model and the function. With no flags, rql shows what the connector asks for, on a page in your browser, and installs it on your answer. Then `rql import cve://recent`, or `rql import cve://kev`.
