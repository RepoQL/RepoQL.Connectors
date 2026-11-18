-- What cve_dependency_findings asks OSV, and what it leaves out, without asking anything: one row per dependency declared in a file whose URI matches the pattern files, with its ecosystem as the dependencies view spells it, the package as the file spells it, the range that applies to it, its pin, the file that states the requirement, and uncertain_because from the dependencies view; then osv_ecosystem, osv_package and osv_version, which are what OSV is sent; and unchecked, which is null when the row is asked and otherwise says why it is not, as cve_osv_question says. Nothing leaves the machine: read it to see what a findings query would send. The range is the requirer's own, or, for a requirement that writes none and takes its version from a pins file, such as a NuGet PackageReference under central package management, the range that file sets, read from dependency_evidence by the requirement's own file, line and name. files is matched with DuckDB's GLOB, in which * matches any characters, slashes included; it takes no ; or ! as a RepoQL glob does.
macro (files) table
SELECT DISTINCT usage.ecosystem, usage.package, usage.range, usage.pin, usage.declared_in, usage.uncertain_because,
       usage.question.ecosystem AS osv_ecosystem, usage.question.package AS osv_package, usage.question.version AS osv_version,
       usage.question.unchecked AS unchecked
FROM (
    SELECT d.ecosystem, d.name AS package, COALESCE(d.range, pinned.range) AS range, d.pin, d.declared_in, d.uncertain_because,
           cve_osv_question(d.ecosystem, d.address, d.version, d.pin, COALESCE(d.range, pinned.range)) AS question
    FROM dependencies AS d
    -- A requirement whose range a pins file sets has no range of its own. Its statement is one line of one file, and
    -- dependency_evidence holds that line with the range the pins file gives it.
    LEFT JOIN dependency_evidence AS pinned
      ON pinned.declared_in = d.declared_in AND pinned.line = d.line AND pinned.name = d.name AND pinned.ecosystem = d.ecosystem
     AND pinned.evidence = 'declared' AND pinned.range_from IS NOT NULL
     AND d.pin = 'minimum' AND d.version IS NULL AND d.range IS NULL
    WHERE d.declared_in GLOB files
) AS usage
