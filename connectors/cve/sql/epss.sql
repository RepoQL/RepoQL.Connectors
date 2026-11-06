-- Every CVE of one cve import with its EPSS score, the probability FIRST gives that it is exploited in the next 30 days, and that score's percentile among all CVEs, on the day EPSS published them, as scores/epss.csv holds them. root is the import's root, as cve_epss('cve://recent/') reads the import cve://recent and cve_epss('cve://kev/') the import cve://kev.
macro (root) table
SELECT * FROM csv_data(root || 'scores/epss.csv')
