// The CVE connector. It copies the CVEs published in the last 30 days into an import whose tree answers a security
// engineer's first questions by its paths alone: what was reported this month, what of it is critical, and what kind
// of software it is in. README.md states the questions it serves, and why it reads the sources it does.
//
// An import is one of two scopes:
//
//   cve://recent  every CVE published in the window, and every CVE CISA lists as known exploited, whatever its age
//   cve://kev     only the CVEs CISA lists as known exploited, whatever their age: under two thousand, read in minutes
//
//   fetch     copies each CVE of the import's scope from NVD, 200 to a page, and the day's EPSS scores of those CVEs
//   analyze   asks a model what type of software each CVE concerns, and places each CVE at its path
//   render    writes each CVE as an RQL object at its path, the scores as one CSV, the overview and type pages, and
//             every weakness of MITRE's CWE list, linked to each other and from each CVE that names them
//
// The sources, which it only reads, with no credential:
//
//   GET  https://services.nvd.nist.gov/rest/json/cves/2.0   CVEs, by the window they were published or last modified in
//   GET  https://api.first.org/data/v1/epss                 the day's exploit likelihood of every CVE, 10,000 to a page
//   POST https://api.osv.dev/v1/querybatch                  the advisories that name a package version: cve_affects only
//   GET  https://cwe-api.mitre.org/api/v1/cwe               MITRE's CWE list, on a full pass: about 22 requests a week
//
// The import database:
//
//   cves/<CVE id>      fetch's: one CVE, cut to what render shows
//   epss/<CVE id>      fetch's: the CVE's EPSS score on the day EPSS last published
//   weaknesses/CWE-<n> fetch's: one CWE weakness or category, cut to what render shows
//   state/cwe          fetch's: the CWE version held
//   state/watermark    fetch's: the newest lastModified NVD has answered, where the next incremental pass starts
//   state/epss         fetch's: the day of the EPSS scores held
//   state/listing      fetch's: present once a full pass has read the whole scope
//   listed (a table)   fetch's: the CVEs the current full pass has listed, so only their scores are kept
//   labels/<CVE id>    analyze's: the model's reading of the CVE
//   placed/<CVE id>    analyze's: the path the CVE's file is at, and the path it last moved from
//
// The files:
//
//   overview.md                                                   what the import holds, by month, severity and type
//   types/<type>.md                                               what one type means, and how many CVEs it holds
//   cves/<YYYY-MM>/<severity>/<type>/<vendor>/<product>/<id>.rqlobject   one CVE
//   rejected/<id>.rqlobject                                       a CVE its numbering authority withdrew
//   scores/epss.csv                                               every held CVE's EPSS score and percentile
//   weaknesses/CWE-<id>.rqlobject                                 one CWE weakness or category, with its relationships
//   weaknesses/README.md                                          the CWE version, and MITRE's copyright and license
import { Connector, InvalidImport, RateLimited, canonicalAddress, compareInstants, markdown, rqlObject, utf8Size, type Answer, type AnalyzeResult, type Changes, type Concept, type FetchResult, type ImportTarget, type ImportUri, type Json, type Question, type Term } from 'repoql:connector';

// =====================================================================================================================
// Customise here
// =====================================================================================================================
//
// This connector is meant to be copied and changed. The choices most copies change are here; the rest of the file is
// written to be read and changed too: the questions the model is asked (QUESTIONS), how severity is chosen
// (severityOf), the path each CVE is filed at (pathOf), and what its object shows (cveObject).

// How many days back cve://recent holds CVEs, by the day NVD published them. It holds every CVE CISA lists as known
// exploited whatever its age, and cve://kev holds only those, so the window decides only the rest. A first read of a
// 30 days is about 17,000 CVEs and 90 requests to NVD, and a year about 210,000 and 1,050. A wider window costs more
// at its first read, and the model is asked about roughly 29% of the CVEs it adds.
const WINDOW_DAYS = 30;

// The types of software whose CVEs are written as files, or undefined for every type, such as
// new Set(['libraries', 'frameworks', 'runtimes']). The rest stay in the import's database. A CVE neither the rules nor
// the model could place yet
// is written whatever this says. The types are the keys of QUESTIONS.type.criteria.
const TYPES_WRITTEN: ReadonlySet<string> | undefined = undefined;

const NVD = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const EPSS = 'https://api.first.org/data/v1/epss';
const CWE_API = 'https://cwe-api.mitre.org/api/v1/cwe';
// MITRE's CWE API answers one unknown id in a list with 404, and about 12 KB a weakness, so 100 to a request.
const CWE_BATCH = 100;
// The view in which every weakness has its parents: the relationships kept are this view's.
const RESEARCH_VIEW = '1000';
const CWE_EXTENDED_KEPT = 800;
// The shape of a weakness row. Raise it when readWeakness keeps something new, and the next pass reads the list again,
// so an import does not wait a week for its full pass to hold what the connector now renders.
const CWE_SHAPE = 2;
// The shape of a CVE record. Raise it when readNvd keeps something new, and the next pass lists every CVE of the scope
// again, as a full pass would, so the import holds what the connector now renders without waiting for its full pass.
const CVE_SHAPE = 3;
const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
// The most pages of 1,000 advisories cve_affects reads for one call. A function has 30 seconds.
const OSV_PAGES = 20;
// NVD answers at most 2,000 to a page. A CVE averages 3 KB and reaches tens of KB, so 200 keeps a page well under the
// 4 MiB a JSON response may hold.
const PAGE = 200;
// NVD refuses a window longer than 120 days.
const WINDOW_LIMIT_DAYS = 120;
const EPSS_PAGE = 10000;
const DAY_MS = 86400000;
// How many CVEs one analyze call asks the model about. The rest are asked by the calls after it.
const DECISIONS_PER_CALL = 25;
// The longest description sent to the model. A longer one is cut, and the instructions say so.
const DESCRIPTION_SENT = 6000;
// The most products, ranges of one product, and references a record keeps, so one CVE that lists hundreds still fits a
// record. A record that names more says how many it names, and its file says how many it keeps.
const KEPT_PRODUCTS = 25;
const KEPT_RANGES = 20;
// The most ranges of one product a CVE's structure shows. Every range kept is in the product's node.
const SHOWN_RANGES = 3;
const KEPT_REFERENCES = 60;
// The source identifiers NVD gives the scores of CISA's analysis and its own.
const CISA_ADP = '134c704f-9b21-4f2e-91b3-4a467353bcc0';
const NVD_SOURCE = 'nvd@nist.gov';

// =====================================================================================================================
// What the model is asked
// =====================================================================================================================

// The types of software a CVE can concern, in the order the tree lists them. `other` is the way out, so a CVE that
// fits none is never forced into one.
const TYPES: Record<string, { title: string; what: string; not_for: string; aliases: string[] }> = {
  libraries: { title: 'Libraries and packages', what: 'A library or package that other software builds on, installed from a package registry such as npm, PyPI, Maven, NuGet, crates.io, RubyGems, Go modules, CPAN or Packagist.', not_for: 'A whole application or server that happens to be distributed as a package.', aliases: ['library', 'package', 'dependency', 'npm package', 'pypi package', 'module', 'crate', 'gem'] },
  frameworks: { title: 'Web and application frameworks', what: 'A framework an application is written in: a web framework, an application server framework, or a UI framework.', not_for: 'A content management system or a plugin for one.', aliases: ['framework', 'web framework', 'Spring', 'Django', 'Rails', 'ASP.NET', 'Express', 'Next.js'] },
  runtimes: { title: 'Language runtimes and SDKs', what: 'A language runtime, compiler, interpreter or standard library: .NET, the JVM, Node.js, Python, Go, Ruby, PHP, or their SDKs.', not_for: 'A third-party library written for one of them.', aliases: ['runtime', 'SDK', 'compiler', 'interpreter', 'standard library', 'stdlib', 'JDK', 'Node.js', 'CPython'] },
  databases: { title: 'Databases', what: 'A database server, engine or data store: PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch, SQLite and the like.', not_for: 'A client library that talks to a database.', aliases: ['database', 'DBMS', 'data store', 'SQL server', 'NoSQL', 'cache server'] },
  servers: { title: 'Servers and middleware', what: 'Server software that serves or routes traffic: web servers, proxies, load balancers, message brokers, mail servers, DNS and directory servers.', not_for: 'A network device sold as hardware, or its firmware.', aliases: ['web server', 'proxy', 'load balancer', 'message broker', 'nginx', 'Apache httpd', 'Kafka', 'mail server'] },
  os: { title: 'Operating systems and kernels', what: 'An operating system, its kernel, its drivers, or a component shipped as part of it: Linux, Windows, macOS, iOS, Android, BSD.', not_for: 'An application that merely runs on an operating system.', aliases: ['operating system', 'kernel', 'Linux kernel', 'Windows', 'driver', 'macOS', 'Android'] },
  cloud: { title: 'Containers and cloud platforms', what: 'Container, orchestration, virtualization or cloud platform software and services: Docker, Kubernetes, hypervisors, cloud services and their agents.', not_for: 'An application deployed in a container.', aliases: ['container', 'Kubernetes', 'Docker', 'cloud', 'hypervisor', 'virtualization', 'orchestration'] },
  devtools: { title: 'Developer tools', what: 'Software developers use to build and ship: source control, CI/CD systems, build tools, package managers, IDEs and editors and their extensions.', not_for: 'A library a project depends on at run time.', aliases: ['developer tools', 'CI', 'build tool', 'IDE', 'git', 'package manager', 'editor extension'] },
  apps: { title: 'Applications', what: 'An end-user or business application: a desktop or mobile app, a browser, a self-hosted web application, or enterprise software such as ERP, CRM or a document system.', not_for: 'A plugin for a content management system, or a library.', aliases: ['application', 'app', 'desktop app', 'mobile app', 'browser', 'enterprise software', 'SaaS', 'web application'] },
  cms: { title: 'Content management systems and plugins', what: 'A content management system or e-commerce platform such as WordPress, Drupal, Joomla or Magento, or a plugin or theme for one.', not_for: 'A general web framework.', aliases: ['WordPress', 'WordPress plugin', 'CMS', 'Drupal', 'Joomla', 'theme', 'plugin', 'Magento'] },
  devices: { title: 'Network devices and firmware', what: 'A hardware device or its firmware: routers, switches, firewalls, VPN appliances, cameras, printers, IoT and industrial control devices.', not_for: 'Server software that runs on a general-purpose computer.', aliases: ['router', 'firewall', 'firmware', 'IoT', 'appliance', 'camera', 'ICS', 'SCADA', 'embedded'] },
  ai: { title: 'AI and machine learning software', what: 'Software that serves, runs, orchestrates or connects AI models: model servers, agent frameworks, LLM gateways and proxies, and MCP servers and clients.', not_for: 'An ordinary application that has added an AI feature.', aliases: ['AI', 'machine learning', 'LLM', 'agent', 'MCP server', 'model server', 'LLM gateway'] },
  other: { title: 'Other', what: 'None of the types above, or the description does not say what the software is.', not_for: 'Software that fits one of the types above.', aliases: ['other', 'unknown type'] },
};
const TYPE_NAMES = Object.keys(TYPES);
// Where a CVE's file goes while neither the rules nor the model can say what type of software it is in.
const UNREAD = 'unclassified';

// The suite's generator reads this object from between the two markers, so keep it a plain object literal.
// BEGIN QUESTIONS
const QUESTIONS = {
  type: {
    type: 'choice',
    instructions: 'A CVE record describes a vulnerability in some software. `vendor`, `product` and `package` are what the record names, and `description` is its text, which may be cut at its end. What type of software is the vulnerability in? Judge the software the vulnerability is in, not the software it is used against.',
    criteria: {
      libraries: { what: 'A library or package that other software builds on, installed from a package registry such as npm, PyPI, Maven, NuGet, crates.io, RubyGems, Go modules, CPAN or Packagist.', not_for: 'A whole application or server that happens to be distributed as a package.', examples: ['an npm package that parses YAML', 'a Perl module that bundles a compression library', 'a Java logging library'] },
      frameworks: { what: 'A framework an application is written in: a web framework, an application server framework, or a UI framework.', not_for: 'A content management system or a plugin for one.', examples: ['Spring Framework', 'Django', 'Next.js'] },
      runtimes: { what: 'A language runtime, compiler, interpreter or standard library: .NET, the JVM, Node.js, Python, Go, Ruby, PHP, or their SDKs.', not_for: 'A third-party library written for one of them.', examples: ['the Go standard library net/http package', 'the .NET runtime', 'CPython'] },
      databases: { what: 'A database server, engine or data store: PostgreSQL, MySQL, MongoDB, Redis, Elasticsearch, SQLite and the like.', not_for: 'A client library that talks to a database.' },
      servers: { what: 'Server software that serves or routes traffic: web servers, proxies, load balancers, message brokers, mail servers, DNS and directory servers.', not_for: 'A network device sold as hardware, or its firmware.' },
      os: { what: 'An operating system, its kernel, its drivers, or a component shipped as part of it: Linux, Windows, macOS, iOS, Android, BSD.', not_for: 'An application that merely runs on an operating system.', examples: ['the Linux kernel', 'a Windows component'] },
      cloud: { what: 'Container, orchestration, virtualization or cloud platform software and services: Docker, Kubernetes, hypervisors, cloud services and their agents.', not_for: 'An application deployed in a container.' },
      devtools: { what: 'Software developers use to build and ship: source control, CI/CD systems, build tools, package managers, IDEs and editors and their extensions.', not_for: 'A library a project depends on at run time.' },
      apps: { what: 'An end-user or business application: a desktop or mobile app, a browser, a self-hosted web application, or enterprise software such as ERP, CRM or a document system.', not_for: 'A plugin for a content management system, or a library.', examples: ['a hospital management system written in PHP', 'a web browser', 'an online exam system'] },
      cms: { what: 'A content management system or e-commerce platform such as WordPress, Drupal, Joomla or Magento, or a plugin or theme for one.', not_for: 'A general web framework.', examples: ['a WordPress plugin', 'a Drupal module'] },
      devices: { what: 'A hardware device or its firmware: routers, switches, firewalls, VPN appliances, cameras, printers, IoT and industrial control devices.', not_for: 'Server software that runs on a general-purpose computer.', examples: ['a router\'s web management interface', 'a VPN appliance'] },
      ai: { what: 'Software that serves, runs, orchestrates or connects AI models: model servers, agent frameworks, LLM gateways and proxies, and MCP servers and clients.', not_for: 'An ordinary application that has added an AI feature.', examples: ['an LLM proxy', 'an MCP server'] },
      other: { what: 'None of the types above, or the description does not say what the software is.' },
    },
  },
};
// END QUESTIONS

// =====================================================================================================================
// How a CVE is read: rules over what its record states
// =====================================================================================================================
//
// Rules read a CVE first. Its type comes from its numbering authority, then the names it gives, then its description,
// then its packages, and a model is asked only when no rule recognises it; its attack vector from its CVSS vector; and whether it executes code from its own words and the weaknesses
// it names. Each rule is a pattern you can read and change. A CVE no rule recognises is unclassified, which is a
// statement that the rules do not know it, not a reading of nothing.
//
// The block between the markers takes no import, so a script can load it as it is to measure the rules.
// BEGIN RULES

// What the rules read of one CVE.
interface Facts { assigner?: string; vendor?: string; product?: string; packages: string[]; description: string; cwes: string[]; vector?: string }

// What they answer. rule names the rule that chose the type, so a wrong type can be traced to the pattern that chose it.
interface Reading { type: string; rule: string; attack_vector?: string; code_execution: boolean }

// A rule matches the names the numbering authority gives (vendor and product), or those and the description too. A
// platform word, such as Android or Node.js, says where software runs, not what it is, so its rules read names only.
type Where = 'names' | 'both';

// The types in the order they are tried: the narrower first, so that a WordPress plugin that mentions MySQL is a cms,
// and a MongoDB driver is a library rather than a database.
const TYPE_RULES: [type: string, where: Where, pattern: RegExp][] = [
  ['cms', 'both', /\b(wordpress|drupal|joomla|typo3|magento|adobe commerce|prestashop|opencart|woocommerce|sharepoint|mediawiki|confluence|craft cms|concrete ?cms|umbraco|sitecore|payload ?cms|apostrophe ?cms|strapi|directus|grav cms|phpmyfaq|yeswiki|thelia|vbulletin|phpbb|xenforo|moodle|adobe experience manager|webcenter content|dotcms|liferay|october ?cms|silverstripe|fuel cms|cms)\b/],
  ['devices', 'names', /\b(pan-os|arubaos|aos-[0-9]+|junos( os)?( evolved)?|fortios|fabric os|nx-os|ios xe|ios xr|fireware os|opnsense|pfsense)\b/],
  ['devices', 'both', /\b(d-link|tp-link|netgear|totolink|tenda|wavlink|zyxel|mikrotik|ubiquiti|hikvision|dahua|mediatek|qualcomm|advantech|moxa|schneider electric|rockwell|simatic|sonicwall|synology|qnap|linksys|draytek|edimax|trendnet|routers?|firmware|ip cameras?|nvr|dvr|access points?|chipsets?|modems?|plc|scada|printers?|ip phones?|bmc|uefi|bios|data domain|session smart router|ngfw|firewall appliance)\b/],
  ['os', 'names', /\b(linux|windows( server| \d+| 1[01])?|macos|mac os x|ipados|ios and ipados|iphone os|watchos|tvos|visionos|android|chromeos|zephyr|solaris|freebsd|openbsd|netbsd|red hat enterprise linux|ubuntu|debian|fedora|harmonyos|qnx|vxworks)\b/],
  ['os', 'both', /\b(linux kernel)\b/],
  ['ai', 'both', /\b(llms?|large language models?|langchain|langflow|llama(\.cpp|index)?|vllm|sglang|ollama|open-?webui|mlflow|kubeflow|pydantic-ai|praisonai|agno|litellm|comfyui|gradio|hugging ?face|model context protocol|mcp server|ai agents?|agentic|retrieval-augmented|inference server|tensorflow|pytorch|onnx ?runtime|triton inference)\b/],
  ['libraries', 'names', /\b(connector|driver|client library|sdk|library|libraries|bindings?|jdbc|odbc|crate|toolkit)\b/],
  ['libraries', 'both', /^[^.]{0,120}\b(is|provides) an? ([\w./+-]+ ){0,6}(library|sdk|package|crate|module|parser|bindings?|toolkit|client)\b/],
  ['apps', 'both', /\b((android|ios|mobile|desktop) (app|application)|browser extension|web browser|chrome|chromium|firefox|thunderbird|safari|microsoft (365|office)|outlook|acrobat|photoshop|illustrator|freerdp|vlc|7-zip|winrar|notepad\+\+|erpnext|jeecg(boot)?|jd edwards|peoplesoft|siebel|e-business suite|splunk|n8n|suitecrm|ofbiz|odoo|nextcloud|owncloud|grafana|kibana|fabric composer)\b/],
  ['databases', 'both', /\b(mysql|mariadb|postgres(ql)?|sqlite|mongodb|redis|valkey|elasticsearch|opensearch|cassandra|couchdb|clickhouse|duckdb|oracle database|sql server|db2|marklogic|essbase|surrealdb|neo4j|influxdb|cockroachdb|kylin|arcadedb|falkordb|memcached|etcd|tidb|timescaledb)\b/],
  ['runtimes', 'names', /\b(java se|openjdk|jdk|jre|openj9|\.net( framework| core)?( \d+(\.\d+)?)?( runtime)?|node\.?js|deno|cpython|python|go standard library|erlang|otp|wasmtime|wasmer|v8|quickjs(-ng)?|glibc|musl|vyper|php)\b/],
  ['servers', 'both', /\b(apache http server|httpd|nginx|tomcat|jetty|iis|haproxy|envoy proxy|traefik|caddy|openssh|bind 9|unbound|exim|postfix|dovecot|sendmail|hmailserver|exchange server|zimbra|asterisk|freeswitch|ws_ftp|samba|squid|varnish|traffic server|apache pulsar|kafka|rabbitmq|activemq|weblogic|websphere|jboss|wildfly|glassfish|datapower|keycloak|openldap|freeradius|openvpn|strongswan|rest data services|security verify access)\b/],
  ['servers', 'names', /\b(server|mail server|web server|ftp server|dns server|application server|proxy|gateway)\b/],
  ['devtools', 'both', /\b(gitea|gitlab|github enterprise|jenkins|teamcity|bamboo|jetbrains|intellij|pycharm|webstorm|phpstorm|rubymine|goland|rider|clion|datagrip|visual studio( code)?|vs ?code|xcode|eclipse ide|virtualenv|npm cli|nvm|gradle|nexus repository|artifactory|sonarqube|argo ?cd|ghidra|octopus (server|deploy)|terraform|ansible|vagrant|jupyter(lab)?)\b/],
  ['cloud', 'both', /\b(kubernetes|openshift|rancher|docker|containerd|podman|kyverno|istio|helm|xen|kvm|qemu|vmware|esxi|vcenter|virtualbox|hyper-v|openstack|incus|lxc|lxd|slurm|amazon web services|azure|google cloud|cloud foundry|nomad|commvault)\b/],
  ['frameworks', 'both', /\b(spring( boot| framework)?|struts|django|flask|fastapi|ruby on rails|laravel|symfony|express\.js|next\.js|nuxt|angular|react|vue\.js|svelte|asp\.net( core)?|blazor|apache camel|wicket|vert\.x|helidon|quarkus|micronaut|backstage|parse-server|qt|kendo ui|coldfusion|soa suite|phoenix framework)\b/],
];

// Numbering authorities that publish CVEs of one type of software: the Linux kernel's, Chrome's, and the WordPress
// ecosystem's, whose CVEs often name a plugin and never say WordPress. They are tried before any other rule.
const ASSIGNER_RULES: [type: string, pattern: RegExp][] = [
  ['os', /^(416baaa9-dc9f-4396-8d5f-8c081fb06d67|cve@kernel\.org)$/],
  ['apps', /^chrome-cve-admin@google\.com$/],
  ['cms', /@(wordfence\.com|wpscan\.com|patchstack\.com)$/],
];

// A package in one of these ecosystems is a library, unless a rule above names it as something else.
const LIBRARY_ECOSYSTEMS = /^pkg:(npm|pypi|maven|nuget|cargo|gem|golang|composer|hex|pub|cpan|swift|cocoapods|conan)\//;

// Weaknesses that are code execution by definition: code, command and expression injection, and template injection.
const CODE_EXECUTION_CWES = new Set(['CWE-77', 'CWE-78', 'CWE-94', 'CWE-95', 'CWE-98', 'CWE-917', 'CWE-1336']);
const CODE_EXECUTION_WORDS = /\b(remote code execution|rce|(execute|execution of|run) (arbitrary|malicious|remote|attacker[- ]controlled|unauthorized) (code|commands?|scripts?|programs?)|(os |shell )?command injection|code injection|arbitrary command)\b/i;

const ATTACK_VECTORS: Record<string, string> = { N: 'network', A: 'adjacent', L: 'local', P: 'physical' };

function readFacts(facts: Facts): Reading {
  const names = `${facts.vendor ?? ''} ${facts.product ?? ''}`.toLowerCase();
  const description = facts.description.toLowerCase();
  // An authority that publishes one type of software decides first: a WordPress plugin named Media Library Assistant is
  // a cms, whatever its name says. Then the names it gives, the description, and the packages.
  const found =
    match('assigner', ASSIGNER_RULES.find(([, pattern]) => pattern.test(facts.assigner ?? ''))) ??
    match('name', TYPE_RULES.find(([, , pattern]) => pattern.test(names))) ??
    match('description', TYPE_RULES.find(([, where, pattern]) => where === 'both' && pattern.test(description))) ??
    (facts.packages.some(purl => LIBRARY_ECOSYSTEMS.test(purl)) ? { type: 'libraries', rule: 'package' } : undefined) ??
    { type: 'unclassified', rule: 'none' };
  const av = /\bAV:([NALP])\b/.exec(facts.vector ?? '')?.[1];
  return {
    ...found,
    ...(av ? { attack_vector: ATTACK_VECTORS[av] } : {}),
    code_execution: CODE_EXECUTION_WORDS.test(facts.description) || facts.cwes.some(cwe => CODE_EXECUTION_CWES.has(cwe)),
  };
}

function match(source: string, rule: readonly [string, ...unknown[]] | undefined): { type: string; rule: string } | undefined {
  return rule ? { type: rule[0], rule: `${source}:${rule[0]}` } : undefined;
}
// END RULES

// =====================================================================================================================
// The records
// =====================================================================================================================

// One CVE, cut to what render shows. Nothing else of NVD's answer is kept.
interface Cve {
  id: string;
  status: string;
  published: string;
  modified: string;
  // NVD's identifier of the CVE Numbering Authority that assigned it: an e-mail address or a UUID.
  assigner: string;
  description: string;
  products: Product[];
  // How many affected products the record names, when it names more than `products` keeps.
  products_total?: number;
  metrics: Metric[];
  cwes: string[];
  references: Reference[];
  kev?: Kev;
  ssvc?: Ssvc;
  // Worked out by fetch from the scores, so a count by severity is one query: see severityOf.
  severity: string;
}

// One product the numbering authority says is affected, as it wrote it. A record with no affected block, as most from
// before 2016 are, names its products only in NVD's CPE configurations, and `from` is then cpe, and `part` the CPE's part:
// a for an application, o for an operating system, h for hardware. `ranges_total` is how many ranges the record states,
// when it states more than `ranges` keeps. `versions` is what a record of an older shape holds in place of `ranges`.
interface Product { vendor?: string; product?: string; package?: string; collection?: string; purl?: string; ranges: Range[]; ranges_total?: number; versions?: string[]; from?: 'cpe'; part?: string }

// One range of affected versions, as bounds: `from` and `through` are affected themselves, `after` and `below` are not.
// `exact` is one version. `text` is what the record wrote where it wrote no version, such as "all versions prior to 2.1".
// `unaffected` is each version from which the record says the range is no longer affected. A range with no bound is
// every version. A bound is the record's own text: nothing here compares two versions.
interface Range { from?: string; after?: string; below?: string; through?: string; exact?: string; text?: string; unaffected?: string[] }

// CISA's SSVC decision points for a CVE: whether it is exploited (none, poc when an exploit is public, or active), whether
// an attacker can automate it (yes or no), and how much control it gives (partial or total).
interface Ssvc { exploitation?: string; automatable?: string; technical_impact?: string }

// One party's CVSS score. `by` is cna, cisa, nvd, or the identifier of another.
interface Metric { by: string; version: string; vector: string; score: number }

interface Reference { url: string; tags: string[] }

// CISA's Known Exploited Vulnerabilities entry, which NVD carries on the CVE.
interface Kev { added: string; due?: string; action?: string; name?: string }

interface Epss { epss: number; percentile: number; date: string }

// The model's reading of one CVE.
// How a CVE was read. The rules decide its attack vector and whether it executes code; they decide its type when they
// recognise it, and the model when they do not, in which case model and type_confidence say so.
interface Label { type: string; rule: string; attack_vector?: string; code_execution: boolean; type_confidence?: number; model?: string }

// Where a CVE's file is, and where it was before analyze last moved it.
interface Placed { path: string; from?: string }

// The cursor of a pass: which step, the window it reads, and where in it.
// Which CVEs an import holds: those published in the window and every known exploited one, or only the known exploited.
type Scope = 'recent' | 'exploited';
interface Target { scope: Scope }

// Where a pass is. A full pass of cve://recent lists the published windows, then the known exploited, then EPSS; a full pass of
// cve://kev lists the known exploited, then EPSS. Any other pass lists the modified windows, then EPSS.
// A full pass, and the first pass that holds no CWE list, then reads MITRE's CWE list before EPSS, in phases: the
// version, every category, the pillars of the Research Concepts view, each pillar's descendants, the weaknesses in
// batches, and one at a time any weakness a CVE names that the view does not hold.
interface Cursor {
  step: 'published' | 'exploited' | 'modified' | 'cwe' | 'epss'; now: string; from?: string; to?: string; at: number; date?: string;
  phase?: 'version' | 'categories' | 'pillars' | 'tree' | 'weaknesses' | 'cited'; version?: string; pillars?: number[]; ids?: number[]; cited?: number[];
}

// =====================================================================================================================
// Memory: how to read the import, true of every import of this connector
// =====================================================================================================================

const CONCEPTS: Concept[] = [
  {
    name: 'CvePathIsMonthSeverityType', category: 'shape', relevance: ['cves/**', 'overview.md', 'types/**'],
    invariant: 'A CVE\'s file is at cves/<month NVD published it>/<severity>/<type>/<vendor>/<product>/<id>.rqlobject, so a glob such as cves/2026-11/critical/** selects by path alone.',
    tags: ['cve', 'path', 'glob', 'month', 'severity', 'type', 'vendor', 'product', 'tree', 'layout'],
    why: 'The month never changes once a CVE is published. The severity and the type can, when a score is added or revised or a model reads the CVE, and the file then moves: link to a CVE by its origin, the cve.org address, never by its file path.',
    depth: ['severity is critical, high, medium, low, none or unscored; unscored means no party has scored it yet.', 'type is a model\'s reading, or unclassified until a model reads it.', 'A CVE its numbering authority withdrew is at rejected/<id>.rqlobject.'],
  },
  {
    name: 'CveSeverityHasOneScorer', category: 'rule', relevance: ['cves/**'],
    invariant: 'A CVE\'s severity is the score of the first party in this order: the numbering authority, then CISA, then NVD, and CVSS 4.0 before 3.1 within each; cvss_source names which.',
    tags: ['cve', 'severity', 'cvss', 'score', 'cna', 'cisa', 'nvd', 'conflict', 'disagree'],
    why: 'Several parties score one CVE and they disagree. NVD no longer scores most CVEs, so the numbering authority\'s own score usually decides. Every party\'s vector is a metric node of the object, so a disagreement is visible rather than averaged away.',
  },
  {
    name: 'CveReadingsAreRulesFirst', category: 'rule', relevance: ['cves/**', 'types/**', 'overview.md'],
    invariant: 'attack_vector is the scorer\'s CVSS vector, code_execution is the CVE\'s own words and weaknesses, and type is a rule\'s reading, or a model\'s when type_rule is model; unclassified means neither could say.',
    tags: ['cve', 'type', 'category', 'classification', 'rules', 'model', 'attack vector', 'network', 'remote code execution', 'rce', 'code execution'],
    why: 'NVD states no type of software. Rules read the names the numbering authority gives, the authority itself, the description and the packages; a model is asked only about a CVE no rule recognises. type_rule names the rule that decided, so a wrong type can be traced to its pattern in connector.ts.',
    example: "SELECT id FROM cve_vulnerabilities WHERE attack_vector = 'network' AND code_execution asks for remote code execution.",
  },
  {
    name: 'CvePathNamesOneProduct', category: 'rule', relevance: ['cves/**'],
    invariant: 'A CVE\'s path, and the vendor and product of cve_vulnerabilities, name only the first product its record lists: ask cve_products, or the products list, for every product.',
    tags: ['cve', 'product', 'products', 'vendor', 'path', 'glob', 'affected', 'cve_products', 'first product', 'count', 'filter'],
    why: 'One record often names many products: a Windows flaw lists every Windows release, and its file is under the first. A glob or a filter on product therefore finds a fraction of the CVEs that name a product, and answers with a count that looks whole.',
    example: "SELECT DISTINCT id FROM cve_products WHERE product ILIKE '%Windows Server 2019%' finds every CVE that names it; a glob on cves/*/*/*/microsoft/windows-server-2019/** finds only those that name it first.",
    depth: ['A record that names more products than a file keeps has the annotation cve.products-cut, and products_total says how many it names.', 'A library that a runtime or an application ships is filed under the library alone: a flaw in Brotli names Brotli, not the Node.js that bundles it.'],
  },
  {
    name: 'CveRangeIsTheRecordsWords', category: 'rule', relevance: ['cves/**'],
    invariant: 'A range of cve_products is the bounds a CVE\'s record states, as text: a version in no range is not thereby unaffected, and first_unaffected is where the record says a range ends, not a fix anyone confirmed.',
    tags: ['cve', 'version', 'range', 'affected', 'unaffected', 'fixed', 'fix version', 'upgrade', 'first_unaffected', 'version_below', 'end of life', 'semver'],
    why: 'An authority writes only the versions it checked. A release line that is past its end of life is usually not listed, though the flaw is in it. Some authorities, Node.js among them, list only the last affected release of each line as one exact version, though every earlier release of the line is affected.',
    depth: ['version_from and version_through are affected themselves; version_after and version_below are not.', 'The bounds are text: SQL compares them as strings, which orders 2.10 before 2.9. Compare versions yourself.', 'A null first_unaffected means the record states no end, not that no fix exists.'],
  },
];

const TERMS: Term[] = [
  ...TYPE_NAMES.map(name => ({ term: name, meaning: `The CVE type ${name}: ${TYPES[name].what}`, aliases: TYPES[name].aliases, scope: ['cves/**', 'types/**', 'overview.md'] }) as Term),
  { term: 'KEV', meaning: 'CISA\'s catalog of Known Exploited Vulnerabilities: a CVE in it is being exploited, and kev_added is the day CISA added it.', aliases: ['known exploited', 'exploited in the wild', 'actively exploited', 'CISA KEV'], scope: ['cves/**', 'overview.md'] },
  { term: 'SSVC', meaning: 'CISA\'s Stakeholder-Specific Vulnerability Categorization of a CVE: exploitation is none, poc when an exploit is public, or active; automatable is yes or no; technical_impact is partial or total.', aliases: ['proof of concept', 'public exploit', 'exploit available', 'PoC', 'automatable', 'wormable'], scope: ['cves/**'] },
  { term: 'EPSS', meaning: 'FIRST\'s Exploit Prediction Scoring System: the probability that a CVE is exploited in the next 30 days, published daily, in scores/epss.csv.', aliases: ['exploit prediction', 'exploit likelihood', 'probability of exploitation'], scope: ['scores/**', 'overview.md'] },
  { term: 'CNA', meaning: 'A CVE Numbering Authority: the organization that assigned a CVE and wrote its record, whose score decides its severity here.', aliases: ['numbering authority', 'assigner', 'CVE assigner'], scope: ['cves/**'] },
];

export default class Cves extends Connector {
  // An import is cve://recent, the CVEs published in the window and every known exploited one, or cve://kev, only the
  // known exploited. The source is not in the URI: a reader asks about CVEs, whichever database they came through.
  static parse(uri: ImportUri): ImportTarget {
    if ((uri.authority !== 'recent' && uri.authority !== 'kev') || uri.path.length > 0 || uri.query.length > 0)
      throw new InvalidImport('A cve import is cve://recent for the CVEs published in the window and every known exploited one, or cve://kev for only the known exploited ones.');
    return uri.authority === 'kev'
      ? { root: 'cve://kev/', target: { scope: 'exploited' }, title: 'CVEs known to be exploited' }
      : { root: 'cve://recent/', target: { scope: 'recent' }, title: 'CVEs published recently, and every one known to be exploited' };
  }

  private scope(): Scope {
    return (this.import?.target as unknown as Target | undefined)?.scope ?? 'recent';
  }

  // ---- fetch --------------------------------------------------------------------------------------------------------

  // A full pass lists every CVE of the scope: those published in the window, in windows of at most 120 days, and those
  // known exploited. It then reads the day's EPSS scores, and removes what it did not list. Any other pass lists what NVD
  // modified since the watermark, keeping the CVEs of the scope, then reads EPSS when it has published a newer day. The
  // cursor carries the instant the pass began, so every call of a pass reads the same windows.
  async fetch(cursor?: string): Promise<FetchResult> {
    const full = this.pass?.full === true;
    const at: Cursor = cursor ? JSON.parse(cursor) as Cursor : this.firstStep(full);
    try {
      if (at.step === 'epss') return this.epssPage(at, full);
      if (at.step === 'cwe') return this.cwePage(at);
      return this.cvePage(at, full);
    } catch (error) {
      if (error instanceof RateLimited) return { cursor: JSON.stringify(at), wait: error.retryAfterSeconds };
      throw error;
    }
  }

  private firstStep(full: boolean): Cursor {
    const now = this.clock.now();
    // Records of an older shape are read again: every CVE of the scope is listed, though only a full pass removes any.
    const watermark = this.db.get<{ shape?: number }>('state', 'cve')?.shape === CVE_SHAPE
      ? this.db.get<{ modified: string }>('state', 'watermark')?.modified
      : undefined;
    if ((full || watermark === undefined) && this.scope() === 'exploited') return { step: 'exploited', now, at: 0 };
    if (full || watermark === undefined)
      return { step: 'published', now, ...windowFrom(isoMinusDays(now, this.windowDays()), now), at: 0 };
    return { step: 'modified', now, ...windowFrom(watermark, now), at: 0 };
  }

  // One page of NVD's listing for the cursor's step, then the next page, the next window, the next step, or EPSS.
  private cvePage(at: Cursor, full: boolean): FetchResult {
    const exploitedOnly = this.scope() === 'exploited';
    const page = this.nvdPage(listingUrl(at, exploitedOnly));
    const oldest = exploitedOnly ? undefined : isoMinusDays(at.now, this.windowDays());
    let newest = this.db.get<{ modified: string }>('state', 'watermark')?.modified;
    const listed: string[] = [];
    for (const item of page.vulnerabilities) {
      const cve = readCve(item);
      if (newest === undefined || compareInstants(cve.modified, newest) > 0) newest = cve.modified;
      // A modified CVE outside the scope is not this import's: one published before the window and not known exploited,
      // or, in cve://kev, one not known exploited.
      if (cve.kev === undefined && (oldest === undefined || compareInstants(cve.published, oldest) < 0)) continue;
      this.db.put<Cve>('cves', cve.id, fit(cve), { time: cve.modified });
      listed.push(cve.id);
    }
    // A full pass records what NVD listed, so the EPSS step keeps scores only for those: NVD's listing alone decides
    // which CVEs the import holds. A query reads nothing as seen, so the record cannot keep a CVE the listing dropped.
    if (full && listed.length > 0) {
      this.db.query('CREATE TABLE IF NOT EXISTS listed (key VARCHAR PRIMARY KEY, pass VARCHAR NOT NULL)');
      this.db.query('INSERT OR REPLACE INTO listed SELECT unnest($1::JSON::VARCHAR[]), $2', [listed, at.now]);
    }
    // The watermark comes from NVD's own times, never this machine's clock, so no change between two passes is skipped.
    if (newest !== undefined) this.db.put('state', 'watermark', { modified: newest });

    if (at.at + page.vulnerabilities.length < page.totalResults && page.vulnerabilities.length > 0)
      return { cursor: JSON.stringify({ ...at, at: at.at + page.vulnerabilities.length }) };
    if (at.step !== 'exploited' && compareInstants(at.to as string, at.now) < 0)
      return { cursor: JSON.stringify({ ...at, ...windowFrom(at.to as string, at.now), at: 0 }) };
    // A known exploited CVE may be years old, so a full pass of cve://recent lists them apart from the window.
    if (at.step === 'published') return { cursor: JSON.stringify({ step: 'exploited', now: at.now, at: 0 } satisfies Cursor) };
    // Every CVE of the scope has now been listed in this shape, or only modified ones were, because all were already.
    this.db.put('state', 'cve', { shape: CVE_SHAPE });
    // The CWE list changes a few times a year, so a full pass reads it, and so does any pass whose rows are of an older
    // shape, or that holds none.
    if (full || this.db.get<{ shape?: number }>('state', 'cwe')?.shape !== CWE_SHAPE) return { cursor: JSON.stringify({ step: 'cwe', phase: 'version', now: at.now, at: 0 } satisfies Cursor) };
    return { cursor: JSON.stringify({ step: 'epss', now: at.now, at: 0 } satisfies Cursor) };
  }

  // One request of MITRE's CWE list for the cursor's phase, then the next request, the next phase, or EPSS.
  private cwePage(at: Cursor): FetchResult {
    const next = (cursor: Partial<Cursor>): FetchResult => ({ cursor: JSON.stringify({ ...at, ...cursor }) });
    switch (at.phase) {
      case 'version': {
        const body = this.cweGet(`${CWE_API}/version`) as { ContentVersion?: unknown; ContentDate?: unknown };
        if (typeof body.ContentVersion !== 'string') throw new Error('MITRE\'s CWE API answered its version with something other than a version.');
        return next({ phase: 'categories', version: `${body.ContentVersion}${typeof body.ContentDate === 'string' ? ` of ${body.ContentDate}` : ''}` });
      }
      case 'categories': {
        const body = this.cweGet(`${CWE_API}/category/all`) as { Categories?: unknown };
        // A full pass removes what it did not read, so only a whole answer may stand for the list: never an empty one.
        if (!Array.isArray(body.Categories) || body.Categories.length === 0) throw new Error('MITRE\'s CWE API answered category/all with no categories, so the pass stops rather than remove them.');
        for (const category of body.Categories as Json[]) this.putWeakness(readCategory(category));
        return next({ phase: 'pillars' });
      }
      case 'pillars': {
        const view = ((this.cweGet(`${CWE_API}/view/${RESEARCH_VIEW}`) as { Views?: { Members?: { CweID?: unknown; ViewID?: unknown }[] }[] }).Views ?? [])[0];
        const pillars = (view?.Members ?? []).filter(member => member.ViewID === RESEARCH_VIEW).map(member => Number(member.CweID)).filter(Number.isInteger);
        if (pillars.length === 0) throw new Error(`MITRE's CWE API answered view ${RESEARCH_VIEW} with no members.`);
        return next({ phase: 'tree', pillars, ids: [], at: 0 });
      }
      case 'tree': {
        const pillars = at.pillars ?? [];
        const ids = new Set(at.ids ?? []);
        // The tree decides which weaknesses the import keeps, so it must be a tree rooted at the pillar asked for: a
        // malformed answer stops the pass rather than remove every weakness under the pillar.
        const tree = this.cweGet(`${CWE_API}/${pillars[at.at]}/descendants?view=${RESEARCH_VIEW}`);
        const root = Array.isArray(tree) ? ((tree[0] as Record<string, Json> | undefined)?.Data as Record<string, Json> | undefined) : undefined;
        if (!Array.isArray(tree) || tree.length === 0 || Number(root?.ID) !== pillars[at.at])
          throw new Error(`MITRE's CWE API answered the descendants of CWE-${pillars[at.at]} with something other than its tree, so the pass stops rather than remove them.`);
        collectIds(tree, ids);
        if (at.at + 1 < pillars.length) return next({ ids: [...ids], at: at.at + 1 });
        // A CVE may name a weakness the view does not hold, such as a deprecated one. A category is read already.
        const held = new Set(this.db.query(`SELECT key FROM kv WHERE collection = 'weaknesses' AND (value->>'abstraction') = 'category'`).map(row => String(row.key)));
        const named = this.db.query(`SELECT DISTINCT unnest(json_extract_string(value, '$.cwes[*]')) AS cwe FROM kv WHERE collection = 'cves'`)
          .map(row => /^CWE-(\d+)$/.exec(String(row.cwe))?.[1]).filter((id): id is string => id !== undefined).map(Number);
        const cited = [...new Set(named)].filter(id => !ids.has(id) && !held.has(`CWE-${id}`)).sort((a, b) => a - b);
        return next({ phase: 'weaknesses', ids: [...ids].sort((a, b) => a - b), cited, at: 0, pillars: undefined });
      }
      case 'weaknesses': {
        const ids = at.ids ?? [];
        const batch = ids.slice(at.at, at.at + CWE_BATCH);
        if (batch.length > 0) {
          const body = this.cweGet(`${CWE_API}/weakness/${batch.join(',')}`) as { Weaknesses?: unknown };
          if (!Array.isArray(body.Weaknesses)) throw new Error('MITRE\'s CWE API answered a batch of weaknesses with something other than weaknesses.');
          const read = (body.Weaknesses as Json[]).map(readWeakness);
          const missing = batch.filter(id => !read.some(weakness => weakness.id === id));
          if (missing.length > 0) throw new Error(`MITRE's CWE API answered a batch without ${missing.slice(0, 5).map(id => `CWE-${id}`).join(', ')}, so the pass stops rather than remove them.`);
          for (const weakness of read) this.putWeakness(weakness);
        }
        if (at.at + CWE_BATCH < ids.length) return next({ at: at.at + CWE_BATCH });
        return next({ phase: 'cited', ids: undefined, at: 0 });
      }
      case 'cited': {
        const cited = at.cited ?? [];
        if (at.at < cited.length) {
          // A CVE may name an id the CWE list does not hold, which MITRE answers with 404: that one is skipped.
          const body = this.cweGet(`${CWE_API}/weakness/${cited[at.at]}`, true) as { Weaknesses?: unknown } | undefined;
          if (Array.isArray(body?.Weaknesses)) for (const weakness of body.Weaknesses as Json[]) this.putWeakness(readWeakness(weakness));
          return next({ at: at.at + 1 });
        }
        this.db.put('state', 'cwe', { version: at.version ?? 'unknown', shape: CWE_SHAPE });
        return { cursor: JSON.stringify({ step: 'epss', now: at.now, at: 0 } satisfies Cursor) };
      }
      default:
        throw new Error(`The cursor names the CWE phase '${String(at.phase)}', which this connector does not read.`);
    }
  }

  private cweGet(url: string, missingIsNone = false): Json | undefined {
    const response = this.http.request({ url });
    if (missingIsNone && response.status === 404) return undefined;
    if (response.status < 200 || response.status > 299) throw new Error(`MITRE's CWE API answered ${url} with HTTP ${response.status}. A pass resumes from this request.`);
    if (response.body === null || typeof response.body !== 'object') throw new Error(`MITRE's CWE API answered ${url} with something other than JSON.`);
    return response.body as Json;
  }

  private putWeakness(weakness: Weakness): void {
    this.db.put<Weakness>('weaknesses', `CWE-${weakness.id}`, weakness);
  }

  // One page of NVD's answer, which must be a well-formed page: anything else throws, so no pass removes a CVE on a
  // doubtful listing.
  private nvdPage(url: string): { totalResults: number; vulnerabilities: Json[] } {
    const response = this.http.request({ url });
    if (response.status === 404)
      throw new Error(`NVD refused the listing ${url} (HTTP 404${response.headers['message'] ? `: ${response.headers['message']}` : ''}).`);
    if (response.status < 200 || response.status > 299)
      throw new Error(`NVD answered the listing ${url} with HTTP ${response.status}. A pass resumes from this page.`);
    const body = response.body as { totalResults?: unknown; vulnerabilities?: unknown } | undefined;
    if (!body || typeof body.totalResults !== 'number' || !Array.isArray(body.vulnerabilities))
      throw new Error(`NVD answered the listing ${url} with something other than a page of CVEs.`);
    return { totalResults: body.totalResults, vulnerabilities: body.vulnerabilities as Json[] };
  }

  // One page of EPSS. A pass that is not full reads EPSS only when it has published a newer day than the import holds,
  // which its first page says. A full pass reads every page, so each held CVE's score is seen by the pass.
  private epssPage(at: Cursor, full: boolean): FetchResult {
    if (full) this.db.query('CREATE TABLE IF NOT EXISTS listed (key VARCHAR PRIMARY KEY, pass VARCHAR NOT NULL)');
    // A pass that is not full first asks for one score, whose day says whether EPSS has published since.
    if (!full && at.date === undefined) {
      const day = this.epssDay();
      if (day === this.db.get<{ date: string }>('state', 'epss')?.date) return this.finish(full);
      return { cursor: JSON.stringify({ ...at, date: day }) };
    }
    const response = this.http.request({ url: `${EPSS}?limit=${EPSS_PAGE}&offset=${at.at}` });
    if (response.status < 200 || response.status > 299)
      throw new Error(`EPSS answered page ${at.at / EPSS_PAGE + 1} with HTTP ${response.status}.`);
    const body = response.body as { total?: unknown; data?: unknown } | undefined;
    if (!body || typeof body.total !== 'number' || !Array.isArray(body.data))
      throw new Error('EPSS answered with something other than a page of scores.');
    const rows = body.data as { cve?: unknown; epss?: unknown; percentile?: unknown; date?: unknown }[];
    const date = at.date ?? (typeof rows[0]?.date === 'string' ? rows[0].date as string : undefined);
    const ids = rows.map(row => typeof row.cve === 'string' ? row.cve : '').filter(id => id !== '');
    const kept = this.held(ids, full ? at.now : undefined);
    for (const row of rows) {
      if (typeof row.cve !== 'string' || !kept.has(row.cve)) continue;
      const epss = Number(row.epss), percentile = Number(row.percentile);
      if (!Number.isFinite(epss) || !Number.isFinite(percentile) || typeof row.date !== 'string')
        throw new Error(`EPSS answered a score for ${row.cve} that is not a probability.`);
      this.db.put<Epss>('epss', row.cve, { epss, percentile, date: row.date }, { time: `${row.date}T00:00:00Z` });
    }
    if (at.at + rows.length < body.total && rows.length > 0)
      return { cursor: JSON.stringify({ ...at, at: at.at + rows.length, date }) };
    if (date !== undefined) this.db.put('state', 'epss', { date });
    return this.finish(full, at.now);
  }

  // Which of `ids` the import holds, read by a query so that no CVE counts as seen by the pass. In a full pass, only the
  // CVEs that pass listed: one NVD no longer lists is removed at its end, and its score with it.
  private held(ids: string[], pass: string | undefined): Set<string> {
    if (ids.length === 0) return new Set();
    const rows = pass === undefined
      ? this.db.query(`SELECT key FROM kv WHERE collection = 'cves' AND key IN (SELECT unnest($1::JSON::VARCHAR[]))`, [ids])
      : this.db.query(`SELECT key FROM listed WHERE pass = $2 AND key IN (SELECT unnest($1::JSON::VARCHAR[]))`, [ids, pass]);
    return new Set(rows.map(row => String(row.key)));
  }

  // The day of the scores EPSS publishes now, from one score.
  private epssDay(): string | undefined {
    const response = this.http.request({ url: `${EPSS}?limit=1&offset=0` });
    if (response.status < 200 || response.status > 299) throw new Error(`EPSS answered with HTTP ${response.status}.`);
    const data = (response.body as { data?: { date?: unknown }[] } | undefined)?.data;
    if (!Array.isArray(data)) throw new Error('EPSS answered with something other than a page of scores.');
    return typeof data[0]?.date === 'string' ? data[0].date : undefined;
  }

  // The end of a pass. Only a full pass listed the whole scope, so only it may remove what it did not see: a CVE that
  // left the scope, one NVD no longer lists, and the score of either.
  private finish(full: boolean, pass?: string): FetchResult {
    if (!full) return {};
    if (pass !== undefined) this.db.query('DROP TABLE IF EXISTS listed');
    this.db.touch('state', ['watermark', 'epss']);
    this.db.put('state', 'listing', { whole: true });
    return { removeUnseen: true };
  }

  private windowDays(): number {
    if (!Number.isInteger(WINDOW_DAYS) || WINDOW_DAYS < 1 || WINDOW_DAYS > 3650) throw new Error(`WINDOW_DAYS is ${WINDOW_DAYS}: make it a whole number of days from 1 through 3650.`);
    return WINDOW_DAYS;
  }

  // ---- analyze ------------------------------------------------------------------------------------------------------

  // Asks the model about each CVE that changed, DECISIONS_PER_CALL a call, and places it. The host keeps every answer by
  // its request, and the request holds only the vendor, product, package and description, so a CVE whose score or
  // references changed is answered again at no cost. A CVE the model cannot answer yet stays unclassified, and the full
  // analyze the host owes for it asks again.
  async analyze({ since, until }: Changes, cursor?: string): Promise<AnalyzeResult> {
    const page = this.db.changes<Cve>('cves', { since, until, after: cursor, limit: DECISIONS_PER_CALL });
    const placed = this.db.getMany<Placed>('placed', page.changed.map(row => row.key));
    for (const row of page.changed) {
      const label = row.value.status === 'Rejected' ? undefined : this.read(row.value);
      if (label) this.db.put<Label>('labels', row.key, label, { time: row.time });
      else this.db.remove('labels', row.key);
      const path = pathOf(row.value, label);
      const was = placed[row.key]?.path ?? provisionalPath(row.value);
      // A CVE that has not moved keeps the place it has, and the move it last made, so a render between two calls
      // still removes the file it moved from.
      if (placed[row.key]?.path === path) continue;
      this.db.put<Placed>('placed', row.key, was === path ? { path } : { path, from: was }, { time: row.time });
    }
    for (const key of page.removed) {
      this.db.remove('labels', key);
      this.db.remove('placed', key);
    }
    return page.next ? { cursor: page.next } : {};
  }

  // How one CVE reads: the rules first, and the model only for a type no rule recognises. When the model has no answer
  // yet, or answers out of shape, the CVE stays unclassified, and the next full analyze asks again.
  private read(cve: Cve): Label {
    const reading = readFacts(factsOf(cve));
    if (reading.type !== UNREAD) return reading;
    const decision = this.llm.decide({ state: stateOf(cve), questions: QUESTIONS as unknown as Record<string, Question> });
    const type = decision?.answers.type as Answer | undefined;
    if (!decision || !type || type.type !== 'choice' || !TYPE_NAMES.includes(type.choice)) {
      if (decision) console.warn(`The model's answer about ${cve.id} holds no type among ${TYPE_NAMES.join(', ')}, so it stays unclassified.`);
      return reading;
    }
    return { ...reading, type: type.choice, rule: 'model', type_confidence: type.confidence, model: decision.model };
  }

  // ---- render -------------------------------------------------------------------------------------------------------

  // Writes each CVE that changed, or whose reading or place changed, at its place, and removes the file it moved from.
  // A CVE whose type the TYPES setting leaves out is not written, and its file is removed. The overview, the type
  // pages and the scores are about the whole import, so they read through queries, which every slice reads alike.
  async render({ since, until, full }: Changes): Promise<void> {
    const types = this.typesWritten();
    const keys = new Set<string>();
    const removed: string[] = [];
    for (const collection of ['cves', 'labels', 'placed']) {
      for (let after: string | undefined; ;) {
        const page = this.db.changes(collection, { since, until, after });
        for (const row of page.changed) keys.add(row.key);
        if (collection === 'cves') removed.push(...page.removed);
        if (!page.next) break;
        after = page.next;
      }
    }
    // A CVE's structure names its weaknesses, so a CVE that names a weakness that changed is written again.
    const weaknessesChanged: string[] = [];
    for (let after: string | undefined; ;) {
      const page = this.db.changes('weaknesses', { since, until, after });
      weaknessesChanged.push(...page.changed.map(row => row.key), ...page.removed);
      if (!page.next) break;
      after = page.next;
    }
    // A query answers at most 10,000 rows, and one weakness can be named by more CVEs than that, so the keys are paged.
    if (weaknessesChanged.length > 0) {
      for (let after = ''; ;) {
        const rows = this.db.query(`SELECT key FROM kv WHERE collection = 'cves' AND key > $2 AND list_has_any(json_extract_string(value, '$.cwes[*]'), $1::JSON::VARCHAR[]) ORDER BY key LIMIT 1000`, [weaknessesChanged, after]);
        for (const row of rows) keys.add(String(row.key));
        if (rows.length < 1000) break;
        after = String(rows[rows.length - 1].key);
      }
    }

    // A CVE gone from the import: its place is still held, because analyze has not run since fetch removed it.
    const gone = this.db.getMany<Placed>('placed', removed);
    for (const key of removed) {
      if (gone[key]) this.files.remove(gone[key].path);
      if (gone[key]?.from) this.files.remove(gone[key].from as string);
    }

    const ordered = [...keys].sort();
    for (let start = 0; start < ordered.length; start += 1000) {
      const slice = ordered.slice(start, start + 1000);
      const cves = this.db.getMany<Cve>('cves', slice);
      const labels = this.db.getMany<Label>('labels', slice);
      const placed = this.db.getMany<Placed>('placed', slice);
      const names = this.weaknessNames(Object.values(cves).flatMap(cve => cve.cwes));
      for (const key of slice) {
        const cve = cves[key];
        if (!cve) continue;
        const label = labels[key];
        const path = placed[key]?.path ?? provisionalPath(cve);
        const from = placed[key]?.from;
        if (from !== undefined && from !== path) this.files.remove(from);
        if (types !== undefined && label !== undefined && cve.status !== 'Rejected' && !types.has(label.type)) {
          this.files.remove(path);
          continue;
        }
        try { this.files.write(path, cveObject(cve, label, names), { origin: originOf(cve.id), time: cve.modified }); }
        catch (error) { this.files.fail(path, String(error)); }
      }
    }

    const scores = this.db.changes('epss', { since, until, limit: 1 });
    if (full || scores.changed.length > 0 || scores.removed.length > 0) this.files.write('scores/epss.csv', this.epssCsv(), { time: this.db.get<{ date: string }>('state', 'epss')?.date });

    const whole = this.db.get('state', 'listing') !== undefined;
    const counts = this.counts();
    this.files.write('overview.md', overviewFile(counts, whole, this.scope() === 'exploited' ? undefined : this.windowDays(), types, this.db.get<{ date: string }>('state', 'epss')?.date), {});
    for (const type of [...TYPE_NAMES, UNREAD]) this.files.write(`types/${type}.md`, typeFile(type, counts), {});

    // A weakness file names its relatives, so when any entry of the CWE list changes, every file is written again: the
    // host leaves alone each one whose bytes come out the same.
    const weaknesses = this.db.changes('weaknesses', { since, until, limit: 1 });
    if (full || weaknesses.changed.length > 0 || weaknesses.removed.length > 0) this.renderWeaknesses(since, until);
    // The README names the CWE version, which the pass's last call records after every weakness is written, so it is
    // written again when the state changes too.
    const state = this.db.changes('state', { since, until, limit: 1 });
    if (full || weaknesses.changed.length > 0 || weaknesses.removed.length > 0 || state.changed.length > 0) this.renderWeaknessesReadme();

    for (const concept of CONCEPTS) this.concepts.set(concept);
    for (const held of this.concepts.list()) if (!CONCEPTS.some(concept => concept.name === held.name)) this.concepts.remove(held.name);
    for (const term of TERMS) this.vocabulary.set(term);
    for (const held of this.vocabulary.list()) if (!TERMS.some(term => term.term === held.term)) this.vocabulary.remove(held.term, held.domain);
  }

  private renderWeaknesses(since: Changes['since'], until: Changes['until']): void {
    // Each file names its relatives, so it reads the whole list through a query, which every slice of a split render
    // reads alike; a slice's own reads see only its keys.
    const all = new Map<number, Weakness>();
    for (const row of this.db.query(`SELECT value::VARCHAR AS value FROM kv WHERE collection = 'weaknesses'`)) {
      const weakness = JSON.parse(String(row.value)) as Weakness;
      all.set(weakness.id, weakness);
    }
    // A removed entry's file goes too: its key is its file's name.
    for (let after: string | undefined; ;) {
      const page = this.db.changes('weaknesses', { since, until, after });
      for (const key of page.removed) this.files.remove(`weaknesses/${key}.rqlobject`);
      if (!page.next) break;
      after = page.next;
    }
    if (all.size === 0) return;
    const reverse = namedBy(all);
    for (const entry of all.values()) {
      const path = `weaknesses/CWE-${entry.id}.rqlobject`;
      try { this.files.write(path, weaknessObject(entry, all, reverse), { origin: cweOrigin(entry.id) }); }
      catch (error) { this.files.fail(path, String(error)); }
    }
  }

  // The names of the weaknesses a slice's CVEs name, read through a query, which every slice of a split render reads alike.
  private weaknessNames(cwes: string[]): Map<string, string> {
    const names = new Map<string, string>();
    const wanted = [...new Set(cwes)];
    if (wanted.length === 0) return names;
    for (const row of this.db.query(`SELECT key, (value->>'name') AS name FROM kv WHERE collection = 'weaknesses' AND key IN (SELECT unnest($1::JSON::VARCHAR[]))`, [wanted]))
      names.set(String(row.key), String(row.name));
    return names;
  }

  private renderWeaknessesReadme(): void {
    const counts = new Map<string, number>();
    for (const row of this.db.query(`SELECT (value->>'abstraction') AS abstraction, count(*) AS n FROM kv WHERE collection = 'weaknesses' GROUP BY 1`))
      counts.set(String(row.abstraction), Number(row.n));
    if (counts.size === 0) return;
    this.files.write('weaknesses/README.md', weaknessesReadme(counts, this.db.get<{ version: string }>('state', 'cwe')?.version ?? 'still being read'), {});
  }

  // The types the TYPES setting writes, or undefined for every type.
  private typesWritten(): ReadonlySet<string> | undefined {
    if (TYPES_WRITTEN === undefined) return undefined;
    const unknown = [...TYPES_WRITTEN].filter(type => !TYPE_NAMES.includes(type));
    if (unknown.length > 0) throw new Error(`TYPES_WRITTEN names ${unknown.join(', ')}, which ${unknown.length === 1 ? 'is not a type' : 'are not types'}. The types are ${TYPE_NAMES.join(', ')}.`);
    return TYPES_WRITTEN;
  }

  // Every held CVE's score, by CVE id, read in pages of a query.
  private epssCsv(): string {
    const lines = ['cve,epss,percentile,date'];
    for (let after = ''; ;) {
      const page = this.db.query(
        `SELECT e.key, e.value->>'epss' AS epss, e.value->>'percentile' AS percentile, e.value->>'date' AS date
         FROM kv e JOIN kv c ON c.collection = 'cves' AND c.key = e.key
         WHERE e.collection = 'epss' AND e.key > $1 ORDER BY e.key LIMIT 5000`, [after]);
      for (const row of page) lines.push(`${row.key},${row.epss},${row.percentile},${row.date}`);
      if (page.length < 5000) return lines.join('\n') + '\n';
      after = String(page[page.length - 1].key);
    }
  }

  // How many CVEs each month, severity and type holds, counted by one query over the CVEs and the model's readings.
  private counts(): Counts {
    const counts: Counts = { total: 0, rejected: 0, byMonth: {}, bySeverity: {}, byType: {}, kev: 0 };
    const rows = this.db.query(
      `SELECT c.value->>'status' AS status, substr(c.value->>'published', 1, 7) AS month, c.value->>'severity' AS severity,
              coalesce(l.value->>'type', $1) AS type, ((c.value->'kev') IS NOT NULL) AS kev, count(*) AS n
       FROM kv c LEFT JOIN kv l ON l.collection = 'labels' AND l.key = c.key
       WHERE c.collection = 'cves'
       GROUP BY ALL ORDER BY ALL`, [UNREAD]);
    for (const row of rows) {
      const n = Number(row.n);
      counts.total += n;
      if (row.status === 'Rejected') { counts.rejected += n; continue; }
      counts.byMonth[String(row.month)] = (counts.byMonth[String(row.month)] ?? 0) + n;
      counts.bySeverity[String(row.severity)] = (counts.bySeverity[String(row.severity)] ?? 0) + n;
      counts.byType[String(row.type)] = (counts.byType[String(row.type)] ?? 0) + n;
      if (row.kev === true) counts.kev += n;
    }
    return counts;
  }

  // ---- functions ----------------------------------------------------------------------------------------------------

  // The OSV advisories that name each package version, asked of OSV in one batch for every row the call is given. OSV
  // answers at most 1,000 advisories a query and a token for the rest, so each query's tokens are followed until it has
  // none, every unfinished query in one request a page. A list is whole or the call fails: a query that still has more
  // after OSV_PAGES pages, or that repeats a token, throws rather than answer part of a list as the whole of it.
  affects(rows: [string | null, string | null, string | null][]): Json[] {
    const answers: string[][] = rows.map(() => []);
    let pending = rows.map((row, index) => ({ row, index, token: undefined as string | undefined, tokens: new Set<string>() }))
      .filter(({ row }) => row.every(value => typeof value === 'string' && value !== ''));
    for (let page = 0; pending.length > 0; page++) {
      if (page === OSV_PAGES)
        throw new Error(`OSV still had more advisories after ${OSV_PAGES} pages of 1,000 for ${pending.map(({ row }) => row.join(' ')).join(', ')}, so cve_affects answers none rather than part of a list. A distribution's kernel can name tens of thousands: ask about application packages.`);
      const response = this.http.request({
        method: 'POST', url: OSV_BATCH, headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: pending.map(({ row: [ecosystem, name, version], token }) => ({ package: { ecosystem, name }, version, ...(token ? { page_token: token } : {}) })) }),
      });
      if (response.status < 200 || response.status > 299) throw new Error(`OSV answered the batch query with HTTP ${response.status}.`);
      const results = (response.body as { results?: unknown } | undefined)?.results;
      if (!Array.isArray(results) || results.length !== pending.length)
        throw new Error(`OSV answered ${Array.isArray(results) ? results.length : 'no'} results to ${pending.length} queries.`);
      const next: typeof pending = [];
      pending.forEach((query, at) => {
        const result = results[at] as { vulns?: { id?: unknown }[]; next_page_token?: unknown } | null;
        for (const vuln of result?.vulns ?? []) if (typeof vuln.id === 'string') answers[query.index].push(vuln.id);
        const token = result?.next_page_token;
        if (typeof token !== 'string' || token === '') return;
        if (query.tokens.has(token)) throw new Error(`OSV answered the same page token twice for ${query.row.join(' ')}.`);
        query.tokens.add(token);
        next.push({ ...query, token });
      });
      pending = next;
    }
    return answers.map(ids => [...new Set(ids)].sort());
  }
}

// =====================================================================================================================
// Reading NVD's answer
// =====================================================================================================================

// One CVE from NVD's answer. A CVE that is not shaped as NVD documents throws, naming it, so the page is not kept.
function readCve(item: Json): Cve {
  const cve = readNvd(item);
  return { ...cve, severity: severityOf(cve).severity };
}

function readNvd(item: Json): Omit<Cve, 'severity'> {
  const cve = (item as { cve?: Record<string, any> } | null)?.cve;
  if (!cve || typeof cve.id !== 'string' || !/^CVE-\d{4}-\d{4,}$/.test(cve.id))
    throw new Error('NVD listed an entry that is not a CVE.');
  for (const field of ['published', 'lastModified', 'vulnStatus', 'sourceIdentifier'])
    if (typeof cve[field] !== 'string') throw new Error(`NVD listed ${cve.id} with no ${field}.`);
  const affected = productsOf(cve);
  const english = (cve.descriptions as { lang?: string; value?: string }[] | undefined)?.find(text => text.lang === 'en')?.value ?? '';
  return {
    id: cve.id,
    status: cve.vulnStatus,
    published: utc(cve.published),
    modified: utc(cve.lastModified),
    assigner: cve.sourceIdentifier,
    description: english.replace(/\p{Cs}/gu, '�'),
    products: affected.products,
    ...(affected.total !== undefined ? { products_total: affected.total } : {}),
    metrics: metricsOf(cve),
    cwes: cwesOf(cve),
    references: referencesOf(cve),
    ...(typeof cve.cisaExploitAdd === 'string' ? { kev: { added: cve.cisaExploitAdd, due: cve.cisaActionDue, action: cve.cisaRequiredAction, name: cve.cisaVulnerabilityName } } : {}),
    ...ssvcOf(cve),
  };
}

// Each address the record cites, once. NVD lists a reference once for each party that cites it, so an older record often
// holds the same address twice, and a reference is an edge, which an object may hold only once: two would refuse the file.
// Two spellings of one address are one too: NVD lists a Fedora announcement both with %40 and with @, and an edge's target
// is decoded.
function referencesOf(cve: Record<string, any>): Reference[] {
  const byAddress = new Map<string, { url: string; tags: Set<string> }>();
  for (const reference of (cve.references ?? []) as { url?: unknown; tags?: unknown }[]) {
    if (typeof reference.url !== 'string' || !/^https?:\/\//.test(reference.url)) continue;
    const url = canonicalAddress(reference.url);
    const key = decoded(url);
    const entry = byAddress.get(key) ?? { url, tags: new Set<string>() };
    if (Array.isArray(reference.tags)) for (const tag of reference.tags) if (typeof tag === 'string') entry.tags.add(tag);
    byAddress.set(key, entry);
  }
  return [...byAddress.values()].slice(0, KEPT_REFERENCES).map(({ url, tags }) => ({ url, tags: [...tags] }));
}

function decoded(url: string): string {
  try { return decodeURIComponent(url); } catch { return url; }
}

// CISA's SSVC decision, which NVD carries among the metrics. CISA decides it for almost every CVE published since 2024,
// and for the known exploited of every age.
function ssvcOf(cve: Record<string, any>): { ssvc?: Ssvc } {
  const decision = ((cve.metrics?.ssvcV203 ?? []) as { source?: string; ssvcData?: { options?: Record<string, unknown>[] } }[])
    .find(metric => metric.source === CISA_ADP)?.ssvcData;
  if (!decision) return {};
  const options: Record<string, unknown> = Object.assign({}, ...(decision.options ?? []));
  const word = (value: unknown) => typeof value === 'string' && value.trim() !== '' ? value.trim().toLowerCase() : undefined;
  const ssvc = stripped({ exploitation: word(options.exploitation), automatable: word(options.automatable), technical_impact: word(options.technicalImpact) }) as Ssvc;
  return Object.keys(ssvc).length > 0 ? { ssvc } : {};
}

// The products the numbering authority says are affected, from its own affected block, which NVD carries as `affected`.
// A record also names products to say they are not affected, or that nobody knows yet, as Red Hat's do for each stream
// it ships: those are no product of the CVE's.
function productsOf(cve: Record<string, any>): { products: Product[]; total?: number } {
  const products: Product[] = [];
  for (const source of (cve.affected ?? []) as { source?: string; affectedData?: Record<string, any>[] }[]) {
    if (source.source !== cve.sourceIdentifier) continue;
    for (const data of source.affectedData ?? []) {
      const ranges = rangesOf(data);
      if (ranges === undefined) continue;
      products.push({
        vendor: named(data.vendor), product: named(data.product), package: named(data.packageName),
        collection: typeof data.collectionURL === 'string' ? data.collectionURL : undefined,
        purl: typeof data.packageURL === 'string' ? data.packageURL : undefined,
        ranges: ranges.slice(0, KEPT_RANGES), ...(ranges.length > KEPT_RANGES ? { ranges_total: ranges.length } : {}),
      });
    }
  }
  // A product with no name at all names nothing, as an older record's "n/a" does.
  const namedProducts = products.filter(entry => entry.vendor || entry.product || entry.package || entry.purl);
  const all = namedProducts.length > 0 ? namedProducts : cpeProductsOf(cve);
  return { products: all.slice(0, KEPT_PRODUCTS), ...(all.length > KEPT_PRODUCTS ? { total: all.length } : {}) };
}

// The affected ranges of one product of a record, or undefined when the record does not say the product is affected.
// A record states a status for the product, `defaultStatus`, and one for each version or range it lists:
//
//   - a listed range that is affected is a range;
//   - a product affected by default, with a range that is unaffected from a version onwards, is affected below it;
//   - a product affected by default, with nothing else to go on, is affected in every version;
//   - a product with no status at all and no versions is one an older record simply names, so it is kept;
//   - a product unaffected or unknown by default, with no affected range, is not affected.
function rangesOf(data: Record<string, any>): Range[] | undefined {
  const versions = (Array.isArray(data.versions) ? data.versions : []) as Record<string, any>[];
  const ranges = versions.filter(version => version.status === 'affected').map(rangeOf);
  if (data.defaultStatus === 'affected') {
    const exceptions: string[] = [];
    for (const version of versions.filter(entry => entry.status === 'unaffected')) {
      const range = rangeOf(version);
      // "Unaffected from 26.4-29, with no end" says every version below 26.4-29 is affected.
      if (range.from !== undefined && range.below === undefined && range.through === undefined) ranges.push({ below: range.from });
      else exceptions.push(rangeWords(range));
    }
    if (ranges.length === 0) ranges.push(exceptions.length > 0 ? { unaffected: exceptions } : {});
  }
  else if (ranges.length === 0 && (data.defaultStatus !== undefined || versions.length > 0)) return undefined;
  const seen = new Set<string>();
  return ranges.filter(range => { const words = rangeWords(range); return seen.has(words) ? false : (seen.add(words), true); });
}

// One version entry of a record as a range. The record gives a start in `version` and an end in `lessThan` or
// `lessThanOrEqual`, or one version alone. Many authorities instead write the comparison inside `version`, as
// ">= 4.0.0, < 4.7.10", and that is read as the bounds it states.
function rangeOf(version: Record<string, any>): Range {
  const written = oneLine(version.version);
  const below = bound(version.lessThan), through = bound(version.lessThanOrEqual);
  const unaffected = ((Array.isArray(version.changes) ? version.changes : []) as { at?: unknown; status?: unknown }[])
    .filter(change => change.status === 'unaffected').map(change => oneLine(change.at)).filter((at): at is string => at !== undefined);
  const fixed = unaffected.length > 0 ? { unaffected } : {};
  if (version.lessThan !== undefined || version.lessThanOrEqual !== undefined) {
    const from = start(written);
    // A range from a version through the same version is that one version, as Node.js writes the last affected release
    // of each line: ">= 22.23.3, <= 22.23.3" would read as a checked range, which it is not.
    if (from !== undefined && from === through && below === undefined) return { exact: from, ...fixed };
    // A range that starts where it ends, as Chrome's "155.0.8059.39 up to 155.0.8059.39", holds no version: it says before.
    return stripped({ from: from !== undefined && from === below ? undefined : from, below, through, ...fixed }) as Range;
  }
  if (written === undefined || start(written) === undefined) return fixed;
  const comparisons = written.split(/\s*,\s*/).map(part => /^(>=|<=|>|<|=)\s*(\S+)$/.exec(part));
  if (comparisons.every(match => match !== null)) {
    const range: Range = {};
    for (const [, sign, value] of comparisons as RegExpExecArray[])
      range[sign === '>=' ? 'from' : sign === '>' ? 'after' : sign === '<' ? 'below' : sign === '<=' ? 'through' : 'exact'] = value;
    return { ...range, ...fixed };
  }
  // One version is a word with a digit in it. Anything else is the record's own prose, kept as it is written.
  return /^\S+$/.test(written) && /\d/.test(written) && !written.includes('*') ? { exact: written, ...fixed } : { text: written, ...fixed };
}

// The version a range starts at, or undefined when the record states none: 0, a placeholder, or a wildcard.
function start(version: string | undefined): string | undefined {
  return version === undefined || /^0(\.0)*$/.test(version) || version === '*' || named(version) === undefined ? undefined : version;
}

// The version a range ends at, or undefined when the record states none: `*`, a wildcard on a name, as Log4j's
// "log4j-core*", or the address Microsoft writes in place of a version. A wildcard on a version, as "3.18.*", is an end.
function bound(version: unknown): string | undefined {
  const end = oneLine(version);
  return end === undefined || !/\d/.test(end) || /[^\d.]\*$/.test(end) || /^https?:\/\//.test(end) ? undefined : end;
}

// One range as comparisons, such as ">= 2.0, < 2.17.1", so that nobody has to know whether "up to" includes its end.
function rangeWords(range: Range): string {
  const bounds = [range.from && `>= ${range.from}`, range.after && `> ${range.after}`, range.below && `< ${range.below}`, range.through && `<= ${range.through}`].filter(Boolean) as string[];
  const open = (range.from ?? range.after) !== undefined && range.below === undefined && range.through === undefined;
  const words = range.text ?? range.exact ?? (bounds.length > 0 ? `${bounds.join(', ')}${open ? ', no upper bound stated' : ''}` : 'every version');
  return range.unaffected?.length ? `${words}, unaffected from ${range.unaffected.join(', ')}` : words;
}

// The ranges of a product as a reader sees them. A record of an older shape holds words in place of ranges.
function rangesIn(product: Product): Range[] {
  return product.ranges ?? (product.versions ?? []).map(text => ({ text }));
}

// The products NVD's analysts name in its CPE configurations, for a record whose numbering authority named none: each
// vendor and product once, applications before operating systems before hardware, with its affected ranges.
function cpeProductsOf(cve: Record<string, any>): Product[] {
  const byName = new Map<string, Product>();
  for (const configuration of (cve.configurations ?? []) as { nodes?: { cpeMatch?: Record<string, any>[] }[] }[])
    for (const node of configuration.nodes ?? [])
      for (const match of node.cpeMatch ?? []) {
        if (match.vulnerable !== true || typeof match.criteria !== 'string') continue;
        // cpe:2.3:part:vendor:product:version:update:…, where a backslash escapes a colon inside a field.
        const fields = match.criteria.split(/(?<!\\):/).map((field: string) => field.replace(/\\(.)/g, '$1'));
        const [part, vendor, product, version, update] = [fields[2], cpeName(fields[3]), cpeName(fields[4]), cpeValue(fields[5]), cpeValue(fields[6])];
        if (!vendor && !product) continue;
        const key = `${vendor}:${product}`;
        const entry: Product = byName.get(key) ?? { vendor, product, ranges: [], from: 'cpe' as const, part };
        const range = cpeRange(match, version && update ? `${version} ${update}` : version);
        if (!entry.ranges.some(held => rangeWords(held) === rangeWords(range))) {
          if (entry.ranges.length < KEPT_RANGES) entry.ranges.push(range);
          else entry.ranges_total = (entry.ranges_total ?? KEPT_RANGES) + 1;
        }
        byName.set(key, entry);
      }
  const order = (part: string) => part === 'a' ? 0 : part === 'o' ? 1 : 2;
  return [...byName.values()].sort((a, b) => order(a.part ?? '') - order(b.part ?? ''));
}

function cpeRange(match: Record<string, any>, version: string | undefined): Range {
  const range = stripped({ from: oneLine(match.versionStartIncluding), after: oneLine(match.versionStartExcluding), below: oneLine(match.versionEndExcluding), through: oneLine(match.versionEndIncluding) }) as Range;
  return Object.keys(range).length > 0 || version === undefined ? range : { exact: version };
}

// A CPE vendor or product in words: CPE writes spaces as underscores, so linux_kernel is "linux kernel".
function cpeName(field: string | undefined): string | undefined {
  return named(field?.replace(/_/g, ' '));
}

// A CPE version or update, or undefined for * (any) and - (none).
function cpeValue(field: string | undefined): string | undefined {
  return field === undefined || field === '*' || field === '-' ? undefined : oneLine(field);
}

// A name a record states, or undefined for a placeholder that names nothing.
function named(value: unknown): string | undefined {
  const name = oneLine(value);
  return name === undefined || /^(n\/a|na|-|\*|unknown|unspecified)$/i.test(name) ? undefined : name;
}

// A record's text on one line: authorities write version lists across lines, and a headline or path holds no line break.
function oneLine(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const line = value.replace(/\s+/g, ' ').trim();
  return line === '' ? undefined : line;
}

// Every party's CVSS 3.x and 4.0 score. CVSS 2.0 has no critical level, so it decides nothing here and is not kept.
function metricsOf(cve: Record<string, any>): Metric[] {
  const metrics: Metric[] = [];
  for (const kind of ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']) {
    for (const metric of (cve.metrics?.[kind] ?? []) as { source?: string; cvssData?: Record<string, any> }[]) {
      const data = metric.cvssData;
      if (!data || typeof data.baseScore !== 'number' || typeof data.vectorString !== 'string') continue;
      const by = metric.source === cve.sourceIdentifier ? 'cna' : metric.source === CISA_ADP ? 'cisa' : metric.source === NVD_SOURCE ? 'nvd' : String(metric.source);
      metrics.push({ by, version: String(data.version), vector: data.vectorString, score: data.baseScore });
    }
  }
  return metrics;
}

function cwesOf(cve: Record<string, any>): string[] {
  const cwes = new Set<string>();
  for (const weakness of (cve.weaknesses ?? []) as { description?: { value?: string }[] }[])
    for (const description of weakness.description ?? [])
      if (typeof description.value === 'string' && /^CWE-\d+$/.test(description.value)) cwes.add(description.value);
  return [...cwes].sort();
}

// NVD's instants carry no zone, and are UTC.
function utc(instant: string): string {
  return /(Z|[+-]\d{2}:\d{2})$/.test(instant) ? instant : `${instant}Z`;
}

// A CVE cut until it fits the manifest's 64 KiB: references first, then products, then the description. A record that
// loses products says how many it named.
function fit(cve: Cve): Cve {
  const cut: Cve = { ...cve, references: [...cve.references], products: [...cve.products] };
  while (utf8Size(cut) > 60000 && cut.references.length > 0) cut.references.pop();
  while (utf8Size(cut) > 60000 && cut.products.length > 1) {
    cut.products_total ??= cve.products.length;
    cut.products.pop();
  }
  if (utf8Size(cut) > 60000) cut.description = cut.description.slice(0, 20000);
  return cut;
}

// =====================================================================================================================
// What analyze works out
// =====================================================================================================================

// What the model is shown: the names the record states and its description, nothing it would read as a conclusion.
// What the rules read of one CVE: the names its numbering authority gives, the authority, its packages, description and
// weaknesses, and the CVSS vector that set its severity.
function factsOf(cve: Cve): Facts {
  const first = leadProduct(cve);
  const purls = [...new Set(cve.products.map(entry => entry.purl).filter((purl): purl is string => purl !== undefined))];
  return {
    assigner: cve.assigner, vendor: first?.vendor, product: first?.product ?? first?.package, packages: purls,
    description: cve.description, cwes: cve.cwes, vector: severityOf(cve).metric?.vector,
  };
}

function stateOf(cve: Cve): Json {
  const first = leadProduct(cve);
  const description = cve.description.length > DESCRIPTION_SENT ? cve.description.slice(0, DESCRIPTION_SENT) : cve.description;
  const state: Record<string, Json> = { description };
  if (first?.vendor) state.vendor = first.vendor;
  if (first?.product) state.product = first.product;
  if (first?.package) state.package = first.package;
  return state;
}

// The score that sets a CVE's severity: the numbering authority's, then CISA's, then NVD's, then anyone's, and CVSS 4.0
// before 3.1 before 3.0 within each.
function severityOf(cve: Pick<Cve, 'metrics'>): { severity: string; metric?: Metric } {
  const order = ['cna', 'cisa', 'nvd'];
  const rank = (metric: Metric) => (order.indexOf(metric.by) < 0 ? 3 : order.indexOf(metric.by)) * 10 + (metric.version === '4.0' ? 0 : metric.version === '3.1' ? 1 : 2);
  const metric = [...cve.metrics].sort((a, b) => rank(a) - rank(b))[0];
  if (!metric) return { severity: 'unscored' };
  const score = metric.score;
  return { severity: score === 0 ? 'none' : score < 4 ? 'low' : score < 7 ? 'medium' : score < 9 ? 'high' : 'critical', metric };
}

// A path segment from a name: lowercase letters, digits, dots, underscores and hyphens, at most 64 characters.
function segment(name: string | undefined): string {
  // Accents fold to their letters, so TÜBİTAK is tubitak, not t-bi-tak.
  const slug = (name ?? '').normalize('NFKD').replace(/\p{M}+/gu, '').toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[-.]+|[-.]+$/g, '').slice(0, 64).replace(/[-.]+$/, '');
  return slug === '' ? 'unknown' : slug;
}

// The product a CVE is in, which names its path and which the rules read: the first its numbering authority names, or the
// first NVD's CPEs name when the CPEs of its part, applications say, are of at most three vendors. A flaw NVD finds in the
// applications of more vendors, as in a protocol many implement, is in none of them alone, so it has no lead product,
// though every one is still a node. The distributions that package an application are operating systems, and count not.
const CPE_LEAD_VENDORS = 3;

function leadProduct(cve: Pick<Cve, 'products'>): Product | undefined {
  const first = cve.products[0];
  if (first?.from !== 'cpe') return first;
  return new Set(cve.products.filter(entry => entry.part === first.part).map(entry => entry.vendor)).size <= CPE_LEAD_VENDORS ? first : undefined;
}

// Who makes the software and what it is called: the vendor, or the host of the package's collection; the product, or
// the package's name.
function vendorAndProduct(cve: Cve): [string, string] {
  const first = leadProduct(cve);
  let vendor = first?.vendor;
  if (!vendor && first?.collection) vendor = /^https?:\/\/([^/]+)/.exec(first.collection)?.[1];
  return [segment(vendor), segment(first?.product ?? first?.package)];
}

// Where a CVE's file belongs, given its reading.
function pathOf(cve: Cve, label: Label | undefined): string {
  if (cve.status === 'Rejected') return `rejected/${cve.id}.rqlobject`;
  const [vendor, product] = vendorAndProduct(cve);
  return `cves/${cve.published.slice(0, 7)}/${cve.severity}/${label?.type ?? UNREAD}/${vendor}/${product}/${cve.id}.rqlobject`;
}

// Where render writes a CVE no analyze has placed: its path with no reading.
function provisionalPath(cve: Cve): string {
  return pathOf(cve, undefined);
}

function originOf(id: string): string {
  return `https://www.cve.org/CVERecord?id=${id}`;
}

// =====================================================================================================================
// Weaknesses: MITRE's CWE list
// =====================================================================================================================

// One CWE entry, cut to what render shows: a weakness, with its relationships in the Research Concepts view, or a
// category, with its members. Every other part of MITRE's entry is read on its page, the file's origin.
interface Weakness {
  id: number; abstraction: string; status: string; name: string; description: string; extended?: string;
  likelihood?: string; scopes: string[]; related: [nature: string, cwe: number][];
  // The other names MITRE gives it, such as ReDoS; what it leads to; and where it often occurs, such as Web Based.
  aliases?: string[]; impacts?: string[]; platforms?: string[];
}

function readWeakness(item: Json): Weakness {
  const entry = item as Record<string, Json>;
  const id = Number(entry.ID);
  if (!Number.isInteger(id) || typeof entry.Name !== 'string' || typeof entry.Abstraction !== 'string')
    throw new Error('MITRE\'s CWE API answered a weakness with no id, name or abstraction.');
  const related = new Map<string, [string, number]>();
  for (const relation of (Array.isArray(entry.RelatedWeaknesses) ? entry.RelatedWeaknesses : []) as Record<string, Json>[]) {
    const cwe = Number(relation.CweID);
    if (relation.ViewID === RESEARCH_VIEW && typeof relation.Nature === 'string' && Number.isInteger(cwe)) related.set(`${relation.Nature} ${cwe}`, [relation.Nature, cwe]);
  }
  const scopes = new Set<string>();
  for (const consequence of (Array.isArray(entry.CommonConsequences) ? entry.CommonConsequences : []) as Record<string, Json>[])
    for (const scope of (Array.isArray(consequence.Scope) ? consequence.Scope : [])) if (typeof scope === 'string') scopes.add(scope);
  const extended = oneLineText(entry.ExtendedDescription);
  const aliases = new Set<string>();
  for (const term of (Array.isArray(entry.AlternateTerms) ? entry.AlternateTerms : []) as Record<string, Json>[])
    if (typeof term.Term === 'string' && term.Term.trim() !== '') aliases.add(term.Term.trim());
  const impacts = new Set<string>();
  for (const consequence of (Array.isArray(entry.CommonConsequences) ? entry.CommonConsequences : []) as Record<string, Json>[])
    for (const impact of (Array.isArray(consequence.Impact) ? consequence.Impact : [])) if (typeof impact === 'string') impacts.add(impact);
  // Only where MITRE says it occurs often or sometimes: a platform it lists as undetermined says nothing of the flaw.
  const platforms = new Set<string>();
  for (const platform of (Array.isArray(entry.ApplicablePlatforms) ? entry.ApplicablePlatforms : []) as Record<string, Json>[]) {
    const label = typeof platform.Name === 'string' ? platform.Name : typeof platform.Class === 'string' ? platform.Class : undefined;
    if (label && (platform.Prevalence === 'Often' || platform.Prevalence === 'Sometimes') && !/^Not .*-Specific$/.test(label)) platforms.add(label);
  }
  return {
    ...(aliases.size ? { aliases: [...aliases] } : {}), ...(impacts.size ? { impacts: [...impacts] } : {}), ...(platforms.size ? { platforms: [...platforms] } : {}),
    id, abstraction: entry.Abstraction.toLowerCase(), status: String(entry.Status ?? 'unknown').toLowerCase(), name: entry.Name,
    description: oneLineText(entry.Description) ?? '',
    ...(extended ? { extended: extended.length > CWE_EXTENDED_KEPT ? `${extended.slice(0, CWE_EXTENDED_KEPT - 1).trimEnd()}…` : extended } : {}),
    ...(typeof entry.LikelihoodOfExploit === 'string' ? { likelihood: entry.LikelihoodOfExploit.toLowerCase() } : {}),
    scopes: [...scopes].sort(), related: [...related.values()].sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0])),
  };
}

// A category: a group of weaknesses, such as CWE-264, which some CVEs name in place of a weakness.
function readCategory(item: Json): Weakness {
  const entry = item as Record<string, Json>;
  const id = Number(entry.ID);
  if (!Number.isInteger(id) || typeof entry.Name !== 'string') throw new Error('MITRE\'s CWE API answered a category with no id or name.');
  const members = new Set<number>();
  for (const member of (Array.isArray(entry.Relationships) ? entry.Relationships : []) as Record<string, Json>[]) {
    const cwe = Number(member.CweID);
    if (Number.isInteger(cwe)) members.add(cwe);
  }
  return {
    id, abstraction: 'category', status: String(entry.Status ?? 'unknown').toLowerCase(), name: entry.Name,
    description: oneLineText(entry.Summary) ?? '', scopes: [], related: [...members].sort((a, b) => a - b).map(cwe => ['HasMember', cwe] as [string, number]),
  };
}

function oneLineText(value: Json | undefined): string | undefined {
  const text = typeof value === 'string' ? value.replace(/\s+/g, ' ').trim() : '';
  return text === '' ? undefined : text;
}

// Every weakness id under one node of a view's descendant tree. A node that is not a node with an id throws, so a
// malformed tree never stands for fewer weaknesses than it holds.
function collectIds(node: Json | undefined, ids: Set<number>): void {
  if (node === null || node === undefined) return;
  if (Array.isArray(node)) { for (const child of node) collectIds(child, ids); return; }
  const data = typeof node === 'object' ? (node as Record<string, Json>).Data as Record<string, Json> | undefined : undefined;
  const id = Number(data?.ID);
  if (!Number.isInteger(id)) throw new Error('MITRE\'s CWE API answered a tree with a node that names no weakness, so the pass stops rather than remove any.');
  ids.add(id);
  collectIds((node as Record<string, Json>).Children, ids);
}

// The file of a weakness a CVE names, such as CWE-79. It is the same whatever the weakness is, so a CVE refers to it
// before the list is read, and the reference binds when the file arrives.
function weaknessPath(cwe: string): string | undefined {
  return /^CWE-\d+$/.test(cwe) ? `weaknesses/${cwe}.rqlobject` : undefined;
}

function cweOrigin(id: number): string {
  return `https://cwe.mitre.org/data/definitions/${id}.html`;
}

// How each relationship of the CWE list reads, and the node kind that holds it. A parent is the weakness this one
// specialises, so it EXTENDS it; every other relationship REFERS_TO.
const NATURES: Record<string, { kind: string; words: string }> = {
  ChildOf: { kind: 'child-of', words: 'child of' },
  ParentOf: { kind: 'parent-of', words: 'parent of' },
  CanPrecede: { kind: 'can-precede', words: 'can precede' },
  CanFollow: { kind: 'can-follow', words: 'can follow' },
  PeerOf: { kind: 'peer-of', words: 'peer of' },
  CanAlsoBe: { kind: 'can-also-be', words: 'can also be' },
  Requires: { kind: 'requires', words: 'requires' },
  StartsWith: { kind: 'starts-with', words: 'starts with' },
  Overlaps: { kind: 'overlaps', words: 'overlaps' },
  HasMember: { kind: 'has-member', words: 'has member' },
  MemberOf: { kind: 'member-of', words: 'member of' },
};
// The first sentence of a description, at most 200 characters.
function firstSentence(text: string): string {
  const sentence = text.split(/(?<=[.!?])\s+(?=[A-Z])/)[0]?.trim() ?? '';
  return sentence.length > 200 ? `${sentence.slice(0, 199).trimEnd()}…` : sentence;
}

const natureOf = (nature: string) => NATURES[nature] ?? { kind: nature.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase(), words: nature };

// The relationships each entry is named in from the other end: a parent's children, what can precede it, and the
// categories it is a member of. Its structure says them, since the other entry's file holds the relationship.
function namedBy(all: Map<number, Weakness>): Map<number, [string, number][]> {
  const reverse = new Map<number, [string, number][]>();
  for (const entry of all.values())
    for (const [nature, to] of entry.related) {
      const other = nature === 'ChildOf' ? 'ParentOf' : nature === 'CanPrecede' ? 'CanFollow' : nature === 'HasMember' ? 'MemberOf' : undefined;
      if (other) reverse.set(to, [...(reverse.get(to) ?? []), [other, entry.id]]);
    }
  return reverse;
}

// One weakness or category as an RQL object. Each relationship the entry states is a node whose kind names it, such as
// child-of-407, with the relationship to the other entry's file.
function weaknessObject(entry: Weakness, all: Map<number, Weakness>, reverse: Map<number, [string, number][]>) {
  const { id, abstraction, status, name, description, extended, likelihood, scopes, related } = entry;
  const named = (cwe: number) => all.has(cwe) ? `CWE-${cwe} ${all.get(cwe)!.name}` : `CWE-${cwe}`;
  let object = rqlObject(`weakness.${abstraction}`, `CWE-${id} — ${name}`)
    .withProperties({ id: `CWE-${id}`, title: name, abstraction, status, ...(likelihood ? { likelihood } : {}), scopes })
    .withContent(extended ? `${description}\n\n${extended}` : description || name);
  for (const [nature, cwe] of related) {
    if (!all.has(cwe)) continue;
    const { kind, words } = natureOf(nature);
    object = object.withChildNode(`${kind}-${cwe}`, kind, `${words} ${named(cwe)}`,
      node => node.withRelationship(nature === 'ChildOf' ? 'EXTENDS' : 'REFERS_TO', { file: `weaknesses/CWE-${cwe}.rqlobject` }));
  }
  // The structure is the text semantic search matches the entry on, and its headline is not. So it holds the words a
  // person searches with, its names and what it is and does, and leaves out what every entry says alike: categories,
  // status, and its children, which their own files name. The nodes hold every relationship.
  const { aliases = [], impacts = [], platforms = [] } = entry;
  const lines = [
    `CWE-${id} ${name}${aliases.length ? `, also called ${aliases.slice(0, 4).join(', ')}` : ''}`,
    firstSentence(description) || name,
  ];
  if (abstraction === 'category') {
    const members = related.filter(([, cwe]) => all.has(cwe)).map(([, cwe]) => cwe);
    lines.push(`category of ${members.length} weaknesses${members.length ? `, such as ${members.slice(0, 3).map(named).join('; ')}` : ''}${/deprecated|obsolete/.test(status) ? ` · ${status}` : ''}`);
  } else {
    lines.push([`${abstraction} weakness`, ...(/deprecated|obsolete/.test(status) ? [status] : []), ...(likelihood ? [`likelihood of exploit ${likelihood}`] : []),
      ...(impacts.length ? [`leads to ${impacts.slice(0, 4).join(', ')}`] : []), ...(platforms.length ? [`often in ${platforms.slice(0, 4).join(', ')}`] : [])].join(' · '));
    const parents = related.filter(([nature, cwe]) => nature === 'ChildOf' && all.has(cwe)).map(([, cwe]) => cwe);
    if (parents.length) lines.push(`child of ${parents.map(named).join('; ')}`);
    const precedes = related.filter(([nature, cwe]) => nature === 'CanPrecede' && all.has(cwe)).map(([, cwe]) => cwe);
    if (precedes.length) lines.push(`can lead to ${precedes.slice(0, 3).map(named).join('; ')}`);
    const children = (reverse.get(id) ?? []).filter(([nature]) => nature === 'ParentOf').length;
    if (children) lines.push(`parent of ${children} more specific weakness${children === 1 ? '' : 'es'}`);
  }
  return object.withStructure(lines.join('\n'));
}

function weaknessesReadme(counts: Map<string, number>, version: string): string {
  return [
    '# CWE weaknesses', '',
    `MITRE's Common Weakness Enumeration, content version ${version}, as its CWE API answered it: every weakness of the Research Concepts view, every category, and any other weakness a CVE here names, each at \`weaknesses/CWE-<id>.rqlobject\`. A CVE refers to each weakness it names. A weakness extends its parents, and refers to the weaknesses it can precede, is a peer of, or requires. A category refers to its members.`, '',
    '| Abstraction | Entries | Kind |', '|-------------|--------:|------|',
    ...['pillar', 'class', 'base', 'variant', 'compound', 'category'].map(abstraction => `| ${abstraction} | ${counts.get(abstraction) ?? 0} | \`cve.weakness.${abstraction}\` |`), '',
    'Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE logo are trademarks of The MITRE Corporation.', '',
    'CWE is free to use by any organization or individual for any research, development, and/or commercial purposes, per the [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html). Accordingly, The MITRE Corporation hereby grants you a non-exclusive, royalty-free license to use CWE for research, development, and commercial purposes. Any copy you make for such purposes is authorized on the condition that you reproduce MITRE\'s copyright designation and this license in any such copy.', '',
  ].join('\n');
}

// =====================================================================================================================
// The files
// =====================================================================================================================

function rounded(value: number): number {
  return Math.round(value * 10000) / 10000;
}

// One sentence of a description, for a headline: the first that says something of the flaw. Many advisories open by
// saying what the product is, such as "LiteLLM is a proxy server", and that sentence is skipped.
function titleOf(cve: Cve): string {
  const sentence = flawSentence(cve);
  return sentence.length > 140 ? `${sentence.slice(0, 137).trimEnd()}…` : sentence;
}

// The first sentence of the description that says something of the flaw, whole, at most 600 characters: the structure
// leads with it, and semantic search matches the structure.
function flawSentence(cve: Cve): string {
  const text = cve.description.replace(/\s+/g, ' ').trim();
  if (text === '') return 'no description';
  // A sentence ends at a stop followed by a space and a capital, so the dots of a version such as 1.2.1.0 end none.
  const sentences = text.split(/(?<=[.!?])\s+(?=[A-Z])/).map(sentence => sentence.trim()).filter(sentence => sentence.length > 0);
  const sentence = sentences.find((candidate, index) => index === sentences.length - 1 || !/^[\w.@/ -]{1,60} is an? /.test(candidate)) ?? text;
  return sentence.length > 600 ? `${sentence.slice(0, 599).trimEnd()}…` : sentence;
}

// One CVE as an RQL object: NVD's facts and the model's reading as properties, the description as its content, each
// product, score and fix as a node, its references as references, and what the connector judged as annotations.
// The structure is the text semantic search matches a CVE on, and its headline is not, so it leads with what the flaw
// is, in the words of its description, then where it is, how bad, and which weaknesses it is an instance of, by name.
function cveObject(cve: Cve, label: Label | undefined, weaknessNames: Map<string, string>) {
  const { severity, metric } = severityOf(cve);
  const first = leadProduct(cve);
  const purls = [...new Set(cve.products.map(entry => entry.purl).filter((purl): purl is string => purl !== undefined))].sort();
  const fixes = cve.references.filter(reference => reference.tags.includes('Patch') || /\/commit\/[0-9a-f]{7,40}\b/i.test(reference.url));
  const rejected = cve.status === 'Rejected';
  const properties: Record<string, Json> = {
    id: cve.id, status: cve.status, published: cve.published, modified: cve.modified, assigner: cve.assigner,
    severity, month: cve.published.slice(0, 7), cwes: cve.cwes, packages: purls, known_exploited: cve.kev !== undefined,
    // Every product by name, where vendor and product below name only the one the path is filed under.
    products: [...new Set(cve.products.map(productName).filter((name): name is string => name !== undefined))],
    products_total: cve.products_total ?? cve.products.length,
  };
  // The names the record states, never the path's placeholder for a name it does not.
  const stated = first?.vendor ?? (first?.collection ? /^https?:\/\/([^/]+)/.exec(first.collection)?.[1] : undefined);
  if (stated) properties.vendor = stated;
  if (first?.product ?? first?.package) properties.product = (first?.product ?? first?.package) as string;
  if (metric) Object.assign(properties, { cvss_score: metric.score, cvss_version: metric.version, cvss_vector: metric.vector, cvss_source: metric.by });
  if (cve.kev) Object.assign(properties, { kev_added: cve.kev.added, ...(cve.kev.due ? { kev_due: cve.kev.due } : {}) });
  if (cve.ssvc) Object.assign(properties, cve.ssvc);
  if (cve.products[0]?.from) properties.products_from = cve.products[0].from;
  if (label) Object.assign(properties, {
    type: label.type, type_rule: label.rule, code_execution: label.code_execution,
    ...(label.attack_vector ? { attack_vector: label.attack_vector } : {}),
    ...(label.type_confidence !== undefined ? { type_confidence: rounded(label.type_confidence) } : {}),
    ...(label.model ? { read_by: label.model } : {}),
  });
  else if (!rejected) properties.type = UNREAD;

  // The kind names the severity and the type, as the path does, so each pair is a semantic media type of its own, such
  // as kind=cve.vulnerability.critical.libraries, and the dashboard gives each its own colour and legend entry.
  const kind = rejected ? 'vulnerability.rejected' : `vulnerability.${severity}.${label?.type ?? UNREAD}`;
  let object = rqlObject(kind, `${cve.id} — ${rejected ? 'rejected by its numbering authority' : titleOf(cve)}`).withProperties(properties);
  object = cve.description.trim() === '' ? object.withMarkdown('*NVD holds no description in English.*') : object.withContent(cve.description);
  // Each weakness the CVE names that the CWE list holds is a relationship to that weakness's file.
  for (const cwe of cve.cwes) {
    const path = weaknessPath(cwe);
    if (path) object = object.withFileReference(path);
  }

  // Each product is a node, with its ranges as words in `versions` and as bounds in `ranges`, which cve_products reads.
  cve.products.forEach((entry, index) => {
    const ranges = rangesIn(entry);
    object = object.withChildNode(`product-${index + 1}`, 'product', productLine(entry, ranges.length), node =>
      node.withProperties(stripped({
        vendor: entry.vendor, product: entry.product, package: entry.package, purl: entry.purl, collection: entry.collection,
        versions: ranges.map(rangeWords), ranges: ranges.map(range => ({ ...range, range: rangeWords(range) })) as Json,
        ranges_total: entry.ranges_total, from: entry.from,
      })));
  });
  cve.metrics.forEach((entry, index) => {
    object = object.withChildNode(`score-${index + 1}`, 'score', `CVSS ${entry.version} ${entry.score} from ${scorerWords(entry.by)}`, node =>
      node.withProperties({ by: entry.by, version: entry.version, score: entry.score, vector: entry.vector }));
  });
  fixes.forEach((entry, index) => {
    object = object.withChildNode(`fix-${index + 1}`, 'fix', `A fix: ${markdown.inline(entry.url)}`, node => node.withProperties({ url: entry.url }));
  });
  object = object.withReferences(cve.references.map(reference => reference.url));

  if (cve.kev)
    object = object.withAnnotation('warning', `CISA lists ${cve.id} as known exploited since ${cve.kev.added}${cve.kev.due ? `, with action due ${cve.kev.due}` : ''}.`,
      { rule: 'cve.known-exploited', details: stripped({ added: cve.kev.added, due: cve.kev.due }) });
  if (!rejected && (label?.type ?? UNREAD) === UNREAD)
    object = object.withAnnotation('info', 'Neither the rules nor the model could say what type of software it is in yet, so its type is unclassified. That is not a reading of nothing.', { rule: 'cve.unread' });
  if (cve.products_total !== undefined && cve.products_total > cve.products.length)
    object = object.withAnnotation('info', `The record names ${cve.products_total} affected products, and this file keeps the first ${cve.products.length}. Read the rest at ${originOf(cve.id)}.`,
      { rule: 'cve.products-cut', details: { named: cve.products_total, kept: cve.products.length } });
  if (rejected)
    object = object.withAnnotation('info', 'Its numbering authority rejected it: it is not a vulnerability record, and no product is affected.', { rule: 'cve.rejected' });

  const structure = rejected
    ? ['rejected by its numbering authority', `published ${cve.published.slice(0, 10)} · rejected ${cve.modified.slice(0, 10)}`]
    : [
      flawSentence(cve),
      ...productLines(cve, first),
      `${severity}${metric ? ` (CVSS ${metric.version} ${metric.score} from ${scorerWords(metric.by)})` : ''} · ${label ? label.type : UNREAD}${label?.attack_vector ? ` · ${label.attack_vector} attack` : ''}${label?.code_execution ? ' · code execution' : ''}${exploitWords(cve)}`,
      ...(cve.cwes.length > 0 ? [`weaknesses ${cve.cwes.map(cwe => weaknessNames.has(cwe) ? `${cwe} ${weaknessNames.get(cwe)}` : cwe).join('; ')}`] : []),
      ...(purls.length > 0 ? [`packages ${purls.join(', ')}`] : []),
      fixes.length > 0 ? `fix referenced, in fix-1${fixes.length > 1 ? ` to fix-${fixes.length}` : ''}` : 'no fix referenced',
      `published ${cve.published.slice(0, 10)} · modified ${cve.modified.slice(0, 10)} · ${cve.status}`,
    ];
  return object.withStructure(structure.join('\n'));
}

// A product's name as the record states it: its vendor and its product, or its package, or its package URL.
function productName(entry: Product): string | undefined {
  return [entry.vendor, entry.product ?? entry.package].filter(Boolean).join(' ') || entry.purl;
}

// One product and its affected ranges on a line, such as "Apache Log4j2 — >= 2.13.0, < 2.15.0". It shows `shown` ranges
// and says how many more the node holds, and how many more the record states than the node keeps.
function productLine(entry: Product, shown: number): string {
  const ranges = rangesIn(entry);
  const total = entry.ranges_total ?? ranges.length;
  const words = ranges.slice(0, shown).map(rangeWords);
  if (total > words.length) words.push(`and ${total - words.length} more range${total - words.length === 1 ? '' : 's'}`);
  return `${productName(entry) ?? 'an unnamed product'}${words.length > 0 ? ` — ${words.join('; ')}` : ''}`;
}

// The lines of a CVE's structure that say where the flaw is: every product the file keeps, by name, each with its
// first ranges, so a search for any of them finds the CVE and not only a search for the one its path names. The lead
// product, which the path is filed under, comes first.
function productLines(cve: Cve, first: Product | undefined): string[] {
  if (cve.products.length === 0) return ['no product named'];
  const total = cve.products_total ?? cve.products.length;
  const lines = [...(first ? [first] : []), ...cve.products.filter(entry => entry !== first)].map(entry => productLine(entry, SHOWN_RANGES));
  if (cve.products.length > 1 || total > 1)
    lines.push(total > cve.products.length
      ? `${total} affected products named: this file keeps the first ${cve.products.length}, in product-1 to product-${cve.products.length}`
      : `${total} affected products, in product-1 to product-${total}`);
  return lines;
}

// What is known of its exploitation, in the words someone would search for: CISA's catalog first, then CISA's SSVC
// decision, which says when an exploit is public before anyone is seen using it.
function exploitWords(cve: Cve): string {
  const words: string[] = [];
  if (cve.kev) words.push(`known exploited since ${cve.kev.added}`);
  else if (cve.ssvc?.exploitation === 'active') words.push('exploited, per CISA');
  else if (cve.ssvc?.exploitation === 'poc') words.push('exploit public');
  if (cve.ssvc?.automatable === 'yes') words.push('automatable');
  return words.map(word => ` · ${word}`).join('');
}

function scorerWords(by: string): string {
  return by === 'cna' ? 'the numbering authority' : by === 'cisa' ? 'CISA' : by === 'nvd' ? 'NVD' : by;
}

function stripped(values: Record<string, Json | undefined>): Record<string, Json> {
  const out: Record<string, Json> = {};
  for (const [name, value] of Object.entries(values)) if (value !== undefined) out[name] = value;
  return out;
}

interface Counts { total: number; rejected: number; byMonth: Record<string, number>; bySeverity: Record<string, number>; byType: Record<string, number>; kev: number }

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none', 'unscored'];

// What the import holds, in one read, with a form for while the first full pass is still arriving.
// windowDays is undefined for cve://kev, which holds only the known exploited CVEs.
function overviewFile(counts: Counts, whole: boolean, windowDays: number | undefined, types: ReadonlySet<string> | undefined, epssDate: string | undefined): string {
  const scope = windowDays === undefined
    ? 'the CVEs CISA lists as known exploited, whatever their age'
    : `the CVEs published in the last ${windowDays} days, and every CVE CISA lists as known exploited, whatever its age`;
  const lines = [windowDays === undefined ? '# CVEs known to be exploited' : '# CVEs published recently, and every one known to be exploited', ''];
  lines.push(whole
    ? `This import holds ${scope}: ${counts.total - counts.rejected} CVEs, and ${counts.rejected} withdrawn by their numbering authority. ${counts.kev} are known exploited. NVD is where they are read from.`
    : `The first full read of NVD is still arriving: ${counts.total - counts.rejected} CVEs so far, of ${scope}.`);
  lines.push('', `A CVE is at \`cves/<month>/<severity>/<type>/<vendor>/<product>/<id>.rqlobject\`, so \`cves/<month>/critical/**\` is a month's critical CVEs.${types ? ` Only these types are written: ${[...types].join(', ')}.` : ''}`);
  if (epssDate) lines.push('', `Exploit likelihood is in \`scores/epss.csv\`, as EPSS published it on ${epssDate}.`);
  lines.push('', '## By month', '', '| Month | CVEs |', '|-------|-----:|');
  for (const month of Object.keys(counts.byMonth).sort().reverse()) lines.push(`| \`cves/${month}/\` | ${counts.byMonth[month]} |`);
  lines.push('', '## By severity', '', '| Severity | CVEs |', '|----------|-----:|');
  for (const severity of SEVERITIES) lines.push(`| ${severity} | ${counts.bySeverity[severity] ?? 0} |`);
  lines.push('', '## By type', '', '| Type | CVEs | What it is |', '|------|-----:|------------|');
  for (const type of [...TYPE_NAMES, UNREAD]) lines.push(`| [${type}](types/${type}.md) | ${counts.byType[type] ?? 0} | ${type === UNREAD ? 'Neither the rules nor the model could say yet.' : TYPES[type].title} |`);
  return lines.join('\n') + '\n';
}

// What one type means, what it is not, and how many CVEs it holds.
function typeFile(type: string, counts: Counts): string {
  if (type === UNREAD)
    return `# Unclassified CVEs\n\n${counts.byType[UNREAD] ?? 0} CVEs neither the rules nor the model could place yet. Each moves to its type's folder once one can.\n`;
  const meaning = TYPES[type];
  return [`# ${meaning.title}`, '', meaning.what, '', `Not for: ${meaning.not_for}`, '',
    `${counts.byType[type] ?? 0} CVEs, at \`cves/*/*/${type}/**\`. Rules chose each one's type from its numbering authority, vendor, product, packages and description, and a model chose it for those no rule recognised: type_rule says which.`, ''].join('\n');
}

// =====================================================================================================================
// The windows of NVD's listing
// =====================================================================================================================

// NVD's listing for one page of a step: the CVEs published, or modified, in the cursor's window, or every known exploited
// CVE. In cve://kev a modified window asks only for the known exploited.
function listingUrl(at: Cursor, exploitedOnly: boolean): string {
  const page = `resultsPerPage=${PAGE}&startIndex=${at.at}`;
  if (at.step === 'exploited') return `${NVD}?hasKev&${page}`;
  const by = at.step === 'published' ? 'pub' : 'lastMod';
  return `${NVD}?${by}StartDate=${encodeURIComponent(at.from as string)}&${by}EndDate=${encodeURIComponent(at.to as string)}${exploitedOnly ? '&hasKev' : ''}&${page}`;
}

// The window from `from` to at most 120 days later, and never past `now`.
function windowFrom(from: string, now: string): { from: string; to: string } {
  const end = Math.min(Date.parse(from) + WINDOW_LIMIT_DAYS * DAY_MS, Date.parse(now));
  return { from: iso(Date.parse(from)), to: iso(end) };
}

function isoMinusDays(instant: string, days: number): string {
  return iso(Date.parse(instant) - days * DAY_MS);
}

// NVD's form of an instant: milliseconds and Z.
function iso(ms: number): string {
  return new Date(ms).toISOString();
}

