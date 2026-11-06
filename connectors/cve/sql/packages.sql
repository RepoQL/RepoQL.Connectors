-- One row per package URL a CVE's numbering authority names, such as pkg:cpan/XS-libbrotli, with the CVE's id, severity and type: the CVEs a package registry's name joins on. A purl names no version: the CVE's products say which versions are affected.
view
SELECT id, unnest(packages) AS purl, severity, type, uri
FROM cve_vulnerabilities
WHERE len(packages) > 0
