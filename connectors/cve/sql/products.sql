-- One row per product a CVE's record says is affected, and per range of versions it states for that product: every product of a CVE, where cve_vulnerabilities names only the first. vendor, product, package and purl are the record's names for it. range is the range as comparisons, such as '>= 2.0, < 2.17.1'. Its bounds are version_from and version_through, which are affected themselves, version_after and version_below, which are not, and version_exact for one version; all are null for every version, or where the record wrote prose, which range then holds. first_unaffected is where the record says the range ends: version_below, or the first version it says is no longer affected; null means the record states no end, not that no fix exists. A bound is the record's own text, never a parsed version, so compare versions yourself: as strings, 2.10 sorts before 2.9. A version in no range is not thereby unaffected: an authority lists what it checked, and often no release line past its end of life. A product with no stated range has one row, with null bounds. severity, cvss_score, type and known_exploited are the CVE's. product_uri is the product's node, and uri the CVE's object.
view
SELECT id, vendor, product, package, purl,
       json_extract_string(stated, '$.range') AS range,
       json_extract_string(stated, '$.from') AS version_from,
       json_extract_string(stated, '$.after') AS version_after,
       json_extract_string(stated, '$.below') AS version_below,
       json_extract_string(stated, '$.through') AS version_through,
       json_extract_string(stated, '$.exact') AS version_exact,
       COALESCE(json_extract_string(stated, '$.below'), json_extract_string(stated, '$.unaffected[0]')) AS first_unaffected,
       severity, cvss_score, type, known_exploited, products_from, product_uri, uri
FROM (
    SELECT v.id,
           json_extract_string(n.properties, '$.vendor') AS vendor,
           COALESCE(json_extract_string(n.properties, '$.product'), json_extract_string(n.properties, '$.package')) AS product,
           json_extract_string(n.properties, '$.package') AS package,
           json_extract_string(n.properties, '$.purl') AS purl,
           unnest(CASE WHEN COALESCE(json_array_length(n.properties, '$.ranges'), 0) = 0 THEN [NULL::JSON]
                       ELSE TRY_CAST(json_extract(n.properties, '$.ranges') AS JSON[]) END) AS stated,
           v.severity, v.cvss_score, v.type, v.known_exploited, v.products_from, n.uri AS product_uri, v.uri
    FROM rqlobject_nodes AS n
    JOIN cve_vulnerabilities AS v ON v.uri = n.document_uri
    WHERE n.kind = 'cve.product'
) AS products
