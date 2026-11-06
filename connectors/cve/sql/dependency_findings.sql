-- One row per dependency, declared in a file whose URI matches the pattern files, that an OSV advisory names at its version: the ecosystem, the package and version as the code declares them, the file that declares it, and the advisories' ids, such as GHSA-5crp-9r3c-p9vr. Pass 'file:///**' for this repository alone, 'file:///src/**' for one folder, or '*' for every import too. files is matched with DuckDB's GLOB, in which * matches any characters, slashes included; it takes no ; or ! as a RepoQL glob does. It reads the .NET, Go and Maven dependency views and asks OSV, live, through cve_affects; a dependency no advisory names has no row.
macro (files) table
WITH dependencies AS (
    SELECT 'NuGet' AS ecosystem, package_id AS package, COALESCE(resolved_version, declared_version) AS version, project_uri AS declared_in
    FROM dotnet_package_references
    UNION
    SELECT 'Go', module_path, ltrim(version, 'v'), file_uri
    FROM go_dependencies
    UNION
    SELECT 'Maven', group_id || ':' || artifact_id, version, file_uri
    FROM jvm_dependencies
), asked AS (
    SELECT ecosystem, package, version, declared_in, cve_affects(ecosystem, package, version) AS advisories
    FROM dependencies
    WHERE package IS NOT NULL AND version IS NOT NULL AND version <> '' AND declared_in GLOB files
)
SELECT ecosystem, package, version, declared_in, CAST(advisories AS VARCHAR[]) AS advisories
FROM asked
WHERE json_array_length(advisories) > 0
