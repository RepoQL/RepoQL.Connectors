-- The CVEs NVD modified in the last days days, which includes every one it published in them, newest change first, a row each with what cve_vulnerabilities holds: what a nightly job asks first. To count the CVEs NVD published in a window, filter cve_vulnerabilities on published instead.
macro (days) table
SELECT *
FROM cve_vulnerabilities
WHERE status <> 'Rejected' AND modified >= (now() AT TIME ZONE 'UTC') - to_days(CAST(days AS INTEGER))
ORDER BY modified DESC
