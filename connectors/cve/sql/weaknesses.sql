-- One row per CWE entry a cve import holds: its id (such as CWE-79), name, abstraction (pillar, class, base, variant, compound or category), status, likelihood of exploit, and how many CVEs of the cve imports name it, with the entry's object, whose child-of, can-precede, peer-of, requires and has-member nodes hold its relationships to other entries. A CVE names an entry in its cwes, and refers to the entry's file.
view
SELECT json_extract_string(w.properties, '$.id') AS id,
       json_extract_string(w.properties, '$.title') AS name,
       json_extract_string(w.properties, '$.abstraction') AS abstraction,
       json_extract_string(w.properties, '$.status') AS status,
       json_extract_string(w.properties, '$.likelihood') AS likelihood,
       (SELECT count(DISTINCT v.id) FROM cve_vulnerabilities AS v WHERE list_contains(v.cwes, json_extract_string(w.properties, '$.id'))) AS cves,
       w.headline,
       w.uri
FROM rqlobject_documents AS w
WHERE starts_with(w.kind, 'cve.weakness.')
