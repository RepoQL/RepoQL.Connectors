# RepoQL Connectors

Connectors that copy an outside source into [RepoQL](https://github.com/RepoQL/RepoQL), beside the code it concerns, so an agent can search it, cite it, and ask whether it touches the code.

Each connector works out of the box. Each is also meant to be copied and changed. You change one by editing its code, not by configuring it: the choices most people change sit in a marked block at the top of its `connector.ts`, and the rest is written to be read.

| Connector | What it copies | Install |
|-----------|----------------|---------|
| [cve](connectors/cve) | Publicly reported vulnerabilities from NVD, with exploit likelihood from EPSS and the weaknesses they name from MITRE's CWE list, filed by month, severity and type of software | `rql connector install RepoQL.Connectors.Cve --source https://repoql.github.io/RepoQL.Connectors/index.json` |

## Install one

Every connector is published to this repository's feed, a NuGet v3 feed served by GitHub Pages:

```
https://repoql.github.io/RepoQL.Connectors/index.json
```

Install by package id from that feed:

```
rql connector install RepoQL.Connectors.Cve --source https://repoql.github.io/RepoQL.Connectors/index.json
```

Installing is a grant. rql shows what the connector asks for, such as the hosts it reads and whether it asks a model, on a page in your browser, and installs it only on your answer. Each connector's README says what it reads and what it sends.

## Make one yours

1. Copy the connector's folder into your own repository.
2. Change its code. Start with the block marked "Customise here" at the top of `connector.ts`.
3. Give it your own package id in `manifest.yaml`, under `package`, and raise `package.version` on every change.
4. Run its suites: `node suite.gen.mjs`, then `rql connector test connector.ts --fixtures suite.json`.
5. Pack it and install it: `rql connector pack connector.ts --out .`, then `rql connector install <the .nupkg>`. To publish your own feed, use `rql connector publish`.

## How this repository works

- **Every connector lives in `connectors/<name>/`:** its `connector.ts` and `manifest.yaml`, its SQL views under `sql/`, its help for agents under `help/`, its README, and its suites with the recorded answers they replay.
- **On every pull request**, the pipeline checks that each suite is what its generator writes, then runs every suite.
- **On every push to `main`**, the pipeline packs each connector and publishes any version the feed does not hold to the `gh-pages` branch, which GitHub Pages serves. A published version never changes, so a change to a connector that keeps its version fails the pipeline.

### Until rql reads the package block

A connector's identity, its package id, version and authors, lives in its manifest under `package`. Releases of rql up to 1.7.20 do not read that block yet, and refuse a manifest that has it. Until a release does, `scripts/stage.mjs` copies a connector without the block and prints its identity, and the pipeline passes that to `rql connector pack` as flags. To run a connector's suites locally with such an rql:

```
node scripts/stage.mjs connectors/cve /tmp/cve
rql connector test /tmp/cve/connector.ts --fixtures /tmp/cve/suite.json
```

## License

MIT, except where a connector copies data under its own terms. The CVE connector's copy of MITRE's CWE list carries MITRE's copyright and license, in the `weaknesses/README.md` it writes.
