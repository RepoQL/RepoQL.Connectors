-- What OSV says of one row of the dependencies view: one row with the ecosystem, package and version cve_dependency_findings asks OSV about, as cve_osv_question reads them, and the ids of the advisories that name it, asked live through cve_affects. advisories is an empty list when OSV names none. When the row is not asked, unchecked says why and advisories is null, which is not an empty list: nobody looked. Pass the row's ecosystem, address, version, pin and range, such as cve_dependency_check('cargo', 'rust://crates.io/time', '0.1.43', 'locked', NULL).
macro (ecosystem, address, version, pin, requirement) table
SELECT question.ecosystem, question.package, question.version, question.unchecked,
       CASE WHEN question.unchecked IS NULL THEN CAST(cve_affects(question.ecosystem, question.package, question.version) AS VARCHAR[]) END AS advisories
FROM (SELECT cve_osv_question(ecosystem, address, version, pin, requirement) AS question) AS asked
