-- A version as a key that compares in version order, for a version written as numbers joined by dots, such as 2.10.3 or v10.0.17763.9376: its numbers as a list, so cve_version_key('2.10') > cve_version_key('2.9'), where the texts compare the other way. Trailing zeros are dropped, so 2.0 and 2.0.0 are one key. It is null for every other version: one with a suffix, such as 2.0-beta9, 1.10B02 or 7.1.2-33, a git commit, or prose. Those have no order this can know, so a null key means cannot tell, never equal or lower.
macro (version)
CASE WHEN regexp_full_match(trim(version), 'v?\d{1,18}(\.\d{1,18})*')
     THEN CAST(string_split(regexp_replace(ltrim(trim(version), 'v'), '(\.0+)+$', ''), '.') AS BIGINT[]) END
