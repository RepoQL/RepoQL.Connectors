-- One row per CVE of the cve import: its id, NVD status, when NVD published and last modified it, the month and severity its path is filed under, the CVSS score that sets the severity with its version, vector and scorer (cna, cisa or nvd), the type of software a model read it as with its confidence and its probabilities of remote code execution and of a network attack (type is unclassified until a model reads it), the vendor and product its numbering authority names, its package URLs and weaknesses, and whether CISA lists it as known exploited, since when and with action due when. Lists are VARCHAR[], instants UTC TIMESTAMPs. uri is the CVE's object, whose nodes product-<n>, score-<n> and fix-<n> hold its products, every party's score, and its fixes.
view
SELECT json_extract_string(properties, '$.id') AS id,
       json_extract_string(properties, '$.status') AS status,
       TRY_CAST(json_extract_string(properties, '$.published') AS TIMESTAMP) AS published,
       TRY_CAST(json_extract_string(properties, '$.modified') AS TIMESTAMP) AS modified,
       json_extract_string(properties, '$.month') AS month,
       json_extract_string(properties, '$.severity') AS severity,
       TRY_CAST(json_extract_string(properties, '$.cvss_score') AS DOUBLE) AS cvss_score,
       json_extract_string(properties, '$.cvss_version') AS cvss_version,
       json_extract_string(properties, '$.cvss_vector') AS cvss_vector,
       json_extract_string(properties, '$.cvss_source') AS cvss_source,
       json_extract_string(properties, '$.type') AS type,
       TRY_CAST(json_extract_string(properties, '$.type_confidence') AS DOUBLE) AS type_confidence,
       TRY_CAST(json_extract_string(properties, '$.remote_code_execution') AS DOUBLE) AS remote_code_execution,
       TRY_CAST(json_extract_string(properties, '$.network_attack') AS DOUBLE) AS network_attack,
       json_extract_string(properties, '$.vendor') AS vendor,
       json_extract_string(properties, '$.product') AS product,
       COALESCE(TRY_CAST(json_extract(properties, '$.packages') AS VARCHAR[]), []::VARCHAR[]) AS packages,
       COALESCE(TRY_CAST(json_extract(properties, '$.cwes') AS VARCHAR[]), []::VARCHAR[]) AS cwes,
       COALESCE(TRY_CAST(json_extract_string(properties, '$.known_exploited') AS BOOLEAN), false) AS known_exploited,
       TRY_CAST(json_extract_string(properties, '$.kev_added') AS DATE) AS kev_added,
       TRY_CAST(json_extract_string(properties, '$.kev_due') AS DATE) AS kev_due,
       headline,
       uri
FROM rqlobject_documents
WHERE starts_with(kind, 'cve.vulnerability.')
