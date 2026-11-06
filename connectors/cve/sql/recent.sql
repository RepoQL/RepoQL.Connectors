-- The CVEs NVD published or modified in the last days days, newest first, a row each with what cve_vulnerabilities holds: what a nightly job asks first.
macro (days) table
SELECT *
FROM cve_vulnerabilities
WHERE status <> 'Rejected' AND modified >= (now() AT TIME ZONE 'UTC') - to_days(CAST(days AS INTEGER))
ORDER BY modified DESC
