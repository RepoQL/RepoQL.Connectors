---
description: How to ask a cve import which vulnerabilities were reported, how severe they are, what software they are in, which are exploited, and which of the workspace's dependencies an advisory names — the glob to read or the query to run for each.
tags: [cve, cwe, weakness, weaknesses, cwe_weaknesses, vulnerability, vulnerabilities, security, advisory, nvd, cvss, severity, critical, kev, known exploited, epss, exploit, osv, ghsa, dependency, dependencies, package, purl, affected, reachable, fix, patch, cve_vulnerabilities, cve_recent, cve_known_exploited, cve_packages, cve_dependency_findings, cve_advisories, cve_affects, cve_epss]
---

# Asking a cve import

An import of `cve://recent` holds each CVE published in the last 30 days, or the window its copy of the connector states, and every CVE CISA lists as known exploited whatever its age, as an RQL object. An import of `cve://kev` holds only the known exploited. CISA's listing can lag a CVE's publication by days or weeks, so a new critical CVE can be in `cve://recent` before it is in `cve://kev`. The path files each one by when it was published, how severe it is, and what type of software it is in:

```
cve://recent/cves/<YYYY-MM>/<severity>/<type>/<vendor>/<product>/<CVE id>.rqlobject
```

A glob selects by those alone. `overview.md` counts them, and `types/<type>.md` says what each type means.

| Question | Read | Or query |
|----------|------|----------|
| What was reported this month? | `cve://recent/cves/2026-11/**` | `SELECT * FROM cve_recent(30)` |
| What is critical? | `cve://recent/cves/*/critical/**` | `SELECT id, type, vendor, product FROM cve_vulnerabilities WHERE severity = 'critical'` |
| What is in libraries, or in one vendor's software? | `cve://recent/cves/*/*/libraries/**`, `cve://recent/cves/*/*/*/apache/**` | `SELECT * FROM cve_vulnerabilities WHERE type = 'libraries'` |
| What is being exploited now? | `overview.md` | `SELECT * FROM cve_known_exploited` |
| How likely is exploitation? | `scores/epss.csv` | `SELECT * FROM cve_epss('cve://recent/') ORDER BY epss DESC` |
| Which packages does a CVE name? | the object's `product-<n>` nodes | `SELECT * FROM cve_packages` |
| Which of this repository's dependencies has an advisory? | | `SELECT * FROM cve_dependency_findings('file:///**')`, or `'*'` for every import too |
| Does one package version have one? | | `SELECT * FROM cve_advisories('NuGet', 'Newtonsoft.Json', '12.0.1')` |
| What kind of flaw is it, and what is it related to? | `cve://recent/weaknesses/CWE-79.rqlobject => structure` | `SELECT * FROM cve_weaknesses WHERE id = 'CWE-79'` |
| Which weaknesses recur most? | | `SELECT id, name, cves FROM cve_weaknesses ORDER BY cves DESC` |

## The weaknesses

`weaknesses/CWE-<id>.rqlobject` holds each entry of MITRE's CWE list, and a CVE refers to the file of each weakness it names. A weakness's `child-of-<id>` node extends its parent's file; its `can-precede-<id>`, `peer-of-<id>`, `can-also-be-<id>` and `requires-<id>` nodes refer to the other weakness's file; a category's `has-member-<id>` nodes refer to its members. Its structure names its relatives from both ends. Its kind is its abstraction, such as `cve.weakness.base`. Follow the relationships with `rqlobject_relationships`, or the references of a CVE's file.

## What a CVE object holds

**The object.**
- **Headline:** the id and the first sentence of the description that says something of the flaw.
- **`=> structure`:** what the flaw is, the product and affected versions, its severity and the score that set it, its type, whether it is known exploited, has a public exploit or can be automated, its weaknesses by name, its packages, and whether a fix is referenced, in a few lines. Semantic search matches a CVE on this text, so it leads with the words of its description. A weakness's structure likewise leads with its name, the other names MITRE gives it, such as ReDoS, and what it is.
- **Content:** the description as NVD holds it.
- **Properties:** every fact `cve_vulnerabilities` reads, such as `severity`, `cvss_score`, `cvss_source`, `type`, `type_rule`, `attack_vector`, `code_execution`, `known_exploited`, `kev_added`, `exploitation`, `automatable`, `technical_impact`, `packages` and `cwes`.

**Its nodes,** each read alone by its key:
- `product-<n>`: each product and version range the numbering authority names, or, for a record that names none, as most from before 2016 do, each that NVD's CPE configurations name, with `from: cpe`;
- `score-<n>`: each party's CVSS score, so you can see who disagrees;
- `fix-<n>`: each reference NVD tags as a patch, or that is a commit.

**Annotations:**
- `cve.known-exploited`: CISA lists it as exploited;
- `cve.unread`: neither the rules nor the model could say what type of software it is in;
- `cve.rejected`: its numbering authority withdrew it.

## Reading it right

- **The kind names severity and type.** Each CVE's kind is `cve.vulnerability.<severity>.<type>`, or `cve.vulnerability.rejected`, so `media_type_kind(mime)` and the dashboard's colours tell them apart. It changes when the path does.
- **Each import is its own root.** With both imported, `cve_vulnerabilities` and the views over it hold a known exploited CVE once for each import, and `uri` says which. Pass `cve_epss` the root of the import you mean, such as `cve_epss('cve://kev/')`.
- **Severity has one scorer.** It is the first of: the numbering authority's CVSS, then CISA's, then NVD's, with 4.0 before 3.1. `cvss_source` says which. `unscored` means nobody has scored it yet, not that it is harmless.
- **Type is a rule's reading, or a model's.** `type_rule` says which: a rule names where it matched, such as `name:os` or `assigner:cms`, and `model` means no rule recognised the CVE. `unclassified` means neither could say. `attack_vector` is the scorer's CVSS vector, and `code_execution` the CVE's own words and weaknesses, so `WHERE attack_vector = 'network' AND code_execution` asks for remote code execution.
- **Exploited, or exploitable.** `known_exploited` is CISA's catalog. `exploitation` is CISA's SSVC decision, which it makes for almost every new CVE: `active` is exploited, `poc` means an exploit is public though nobody is yet seen using it, and `none` that neither is known. `WHERE exploitation = 'poc' AND automatable = 'yes'` asks for the CVEs most likely to be exploited next. Null means CISA has not decided, not that no exploit exists.
- **A CVE's file moves when its severity or type changes.** Cite it by its origin, `https://www.cve.org/CVERecord?id=<id>`, never by its path.
- **Whether a CVE affects this code is a question for the code.** Start from `cve_dependency_findings('file:///**')` or the CVE's packages. It matches packages by name, so a component a package embeds, such as a native library or a runtime, is found only by searching the CVEs' products and descriptions. Then read its `fix-<n>` nodes to learn the vulnerable function, and trace that function through the workspace with `explore` and its references.
