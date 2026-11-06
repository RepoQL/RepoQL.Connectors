-- The OSV advisories that name one package at one version, a row each, asked of OSV live through cve_affects: ecosystem is OSV's name for the package's ecosystem, such as NuGet, Go, Maven, npm or PyPI.
macro (ecosystem, package, version) table
SELECT unnest(CAST(cve_affects(ecosystem, package, version) AS VARCHAR[])) AS advisory
