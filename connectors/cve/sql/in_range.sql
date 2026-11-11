-- Whether one version of a product is inside each affected range a CVE's record states for it: one row per CVE, product and range whose vendor and product hold product_name, whatever the case, with in_range 'yes', 'no' or 'cannot tell'. A row with 'yes' comes first, then 'cannot tell', then 'no'. It compares versions written as numbers joined by dots, through cve_version_key, so 2.10 is above 2.9. It answers 'cannot tell', and never guesses, when the version asked or a bound of the range is anything else, such as 2.0-beta9, a build like 1.10B02 or a git commit, when the record wrote prose or no versions for the product, and when a range with no end also says where it stops being affected. 'no' says only that this range does not hold the version: an authority lists the versions it checked and seldom a release line past its end of life, so read every row of the product, and treat 'cannot tell' as a CVE to check by hand. The other columns are those of cve_products.
macro (product_name, version) table
SELECT id, vendor, product, package, range,
       CASE WHEN asked IS NULL OR range IS NULL OR version_text IS NOT NULL THEN 'cannot tell'
            WHEN (key_from IS NOT NULL AND asked < key_from) OR (key_after IS NOT NULL AND asked <= key_after)
              OR (key_below IS NOT NULL AND asked >= key_below) OR (key_through IS NOT NULL AND asked > key_through)
              OR (key_exact IS NOT NULL AND asked <> key_exact) THEN 'no'
            WHEN (version_from IS NOT NULL AND key_from IS NULL) OR (version_after IS NOT NULL AND key_after IS NULL)
              OR (version_below IS NOT NULL AND key_below IS NULL) OR (version_through IS NOT NULL AND key_through IS NULL)
              OR (version_exact IS NOT NULL AND key_exact IS NULL) THEN 'cannot tell'
            WHEN len(unaffected_from) > 0 AND version_below IS NULL AND version_through IS NULL AND version_exact IS NULL THEN 'cannot tell'
            ELSE 'yes' END AS in_range,
       first_unaffected, unaffected_from, severity, cvss_score, type, known_exploited, product_uri, uri
FROM (
    SELECT p.*, cve_version_key(version) AS asked,
           cve_version_key(p.version_from) AS key_from, cve_version_key(p.version_after) AS key_after,
           cve_version_key(p.version_below) AS key_below, cve_version_key(p.version_through) AS key_through,
           cve_version_key(p.version_exact) AS key_exact
    FROM cve_products AS p
    WHERE contains(lower(concat_ws(' ', p.vendor, p.product)), lower(product_name))
) AS ranges
ORDER BY CASE in_range WHEN 'yes' THEN 0 WHEN 'cannot tell' THEN 1 ELSE 2 END, cvss_score DESC NULLS LAST, id, product, range
