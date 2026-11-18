-- What cve_dependency_findings asks OSV about one row of the dependencies view, as a struct: ecosystem is OSV's name for the row's ecosystem, such as crates.io for cargo or PyPI for pypi; package is the package's name on its public registry, read from the row's address; version is the version asked; and unchecked says why the row is not asked, or is null when it is. unchecked is 'no-osv-ecosystem' for an ecosystem OSV has no name for here, such as oci; 'no-version' when no file settles a version; and 'not-the-public-registry' when the address names another registry, or none, because a name on a private registry is another package than the public one of that name, and is not sent to OSV. A NuGet, Maven or Go address names the public registry whatever serves the package, so those are always asked. The version is the row's version, or, for a pin of minimum, the lowest version its requirement admits, which is the lowest the build can take: the version a Go require or a NuGet 1.2.3 writes, or the lower bound of a NuGet interval that includes it, such as [1.2.3, 2.0). Pass a row's ecosystem, address, version, pin and range.
macro (ecosystem, address, version, pin, requirement)
(SELECT {'ecosystem': registry.osv,
         'package': CASE WHEN starts_with(address, registry.head) THEN nullif(substr(address, len(registry.head) + 1), '') END,
         'version': asked,
         'unchecked': CASE WHEN registry IS NULL THEN 'no-osv-ecosystem'
                           WHEN asked IS NULL THEN 'no-version'
                           WHEN address IS NULL OR NOT starts_with(address, registry.head) OR len(address) = len(registry.head) THEN 'not-the-public-registry' END}
 FROM (SELECT CASE ecosystem
                   WHEN 'npm' THEN {'osv': 'npm', 'head': 'npm://registry.npmjs.org/'}
                   WHEN 'nuget' THEN {'osv': 'NuGet', 'head': 'nuget://nuget.org/'}
                   WHEN 'maven' THEN {'osv': 'Maven', 'head': 'maven://repo.maven.apache.org/'}
                   WHEN 'golang' THEN {'osv': 'Go', 'head': 'go://proxy.golang.org/'}
                   WHEN 'pypi' THEN {'osv': 'PyPI', 'head': 'python://pypi.org/'}
                   WHEN 'cargo' THEN {'osv': 'crates.io', 'head': 'rust://crates.io/'}
                   WHEN 'gem' THEN {'osv': 'RubyGems', 'head': 'ruby-gem://rubygems.org/'}
                   WHEN 'composer' THEN {'osv': 'Packagist', 'head': 'composer://repo.packagist.org/'}
              END AS registry,
              CASE WHEN nullif(trim(version), '') IS NOT NULL THEN CASE WHEN ecosystem = 'golang' THEN ltrim(trim(version), 'v') ELSE trim(version) END
                   WHEN pin = 'minimum' AND regexp_full_match(trim(requirement), 'v?\d[0-9A-Za-z.+-]*')
                   THEN CASE WHEN ecosystem = 'golang' THEN ltrim(trim(requirement), 'v') ELSE trim(requirement) END
                   WHEN pin = 'minimum' AND ecosystem = 'nuget' AND regexp_full_match(trim(requirement), '\[\s*\d[0-9A-Za-z.+-]*\s*,[^,]*[\])]')
                   THEN regexp_extract(trim(requirement), '^\[\s*([^,\s]+)', 1)
              END AS asked) AS parts)
