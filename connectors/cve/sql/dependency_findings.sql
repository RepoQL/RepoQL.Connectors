-- One row per dependency, declared in a file whose URI matches the pattern files, that an OSV advisory names at its version: OSV's name for the ecosystem, the package as the file spells it, the version asked, the file that states the requirement, the advisories' ids, such as GHSA-5crp-9r3c-p9vr, and the row's pin and uncertain_because from the dependencies view. Pass 'file:///**' for this repository alone, 'file:///src/**' for one folder, or '*' for every import too. files is matched with DuckDB's GLOB, in which * matches any characters, slashes included; it takes no ; or ! as a RepoQL glob does. It reads every usage of the dependencies view, a lock file's own entries too, in every ecosystem OSV names: npm, NuGet, Maven and Gradle, Go, PyPI, crates.io, RubyGems and Packagist. It asks OSV, live, through cve_affects, once for each package version. A pin of minimum is asked at the lowest version the build can take, so the build may hold a later one. A dependency no advisory names has no row, and neither has one that was never asked: cve_dependency_unchecked lists those, so read it before calling anything clean. cve_dependency_questions shows what would be sent, and sends nothing.
macro (files) table
WITH usages AS MATERIALIZED (
    SELECT * FROM cve_dependency_questions(files) WHERE unchecked IS NULL
), asked AS (
    SELECT ecosystem, package, version, cve_affects(ecosystem, package, version) AS advisories
    FROM (SELECT DISTINCT osv_ecosystem AS ecosystem, osv_package AS package, osv_version AS version FROM usages) AS questions
)
SELECT DISTINCT a.ecosystem, u.package, a.version, u.declared_in, CAST(a.advisories AS VARCHAR[]) AS advisories, u.pin, u.uncertain_because
FROM usages AS u
JOIN asked AS a ON a.ecosystem = u.osv_ecosystem AND a.package = u.osv_package AND a.version = u.osv_version
WHERE json_array_length(a.advisories) > 0
