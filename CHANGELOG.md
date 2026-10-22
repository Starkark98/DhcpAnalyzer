# Changelog

## 1.1.0 (2026-10-22)

### Added
- **Compare two servers (migration)** for 1:1 migrations. In the window choose *Compare two servers (migration)*: source (old) server or a baseline file, target (new) server. The compare dashboard gives a verdict (Equivalent / Review the differences / Not equivalent) and lists every difference by severity (missing on target = critical, different = warning, only on target or cosmetic = info) across scopes, options, exclusions, reservations, policies, classes, option definitions, superscopes, failover and server settings, plus a per-scope overview. Clear errors tell which server could not be read; comparing a server with itself is refused.
- **Baselines**: *Save baseline...* after an analysis (or `-SaveBaseline`) keeps the collected data as `.json`, to compare a new server with it later, also when the old server is already switched off.
- **Easy refresh**: clicking *Analyze* or *Compare* again with the same inputs updates the same report file (a new file is created when the inputs change).
- **Reports as baselines**: besides a baseline `.json`, any analysis report `.html` of DHCP Analyzer can be the source of a comparison. Reports from 1.0.x are accepted: the data they do not contain (policies, classes, option definitions, superscopes) is not compared, and the report says so.
- New data in every analysis: server and scope **policies** (conditions, IP ranges, options, lease), **user and vendor classes**, **option definitions** and **superscopes** (new *Policies* tab in the scope details, new tables in *Server configuration*, superscope in the scope overview).
- Command line: `-CompareWith`, `-Baseline`, `-SaveBaseline`, `-DemoCompare`; the window's demo link follows the selected mode.
- Donations: "Sponsor" button on the GitHub page (`.github/FUNDING.yml`) and a *Support the project* section in the README, both pointing to Ko-fi.

### Changed
- The dashboard styles and common JavaScript are shared by the analyze and compare reports (same Content-Security-Policy hash protection for both).
- README: new *Compare two servers (migrations)* section, updated command line, FAQ, limitations and screenshots.

### Security
- The dashboard now carries a strict Content-Security-Policy: no network access at all, and only its own inline script (pinned by SHA-256 hash) may run. Injected scripts or event handlers are blocked by the browser.
- Every value coming from the DHCP server, the logs or DNS (scope ids and ranges, states, exclusion map entries, failover scope lists, log scope links) is now escaped before being inserted into the page, and numeric fields are forced to numbers. Tested with injection payloads in all fields.
- Removed the inline `onclick` handlers and the CSS selectors built from server data.
- The server name (command line, window, `last.txt`) must be a host name, FQDN or IP address: values with spaces, quotes or a leading `-` are rejected, so they cannot alter the command line used for the UAC relaunch.
- `-OutHtml` must end with `.html`/`.htm`; a folder (also with a trailing `\`) gets the default file name.
- Baseline files and reports used as a source are untrusted input: they must come from DHCP Analyzer (comparison reports and other tools' files are refused), and only their data is taken, parsed and serialized again before going into a compare report (a crafted baseline cannot inject code; tested).
- The audit log path read from the server's configuration must be a local drive path (`X:\...`): UNC paths and `..` are refused, so a server cannot make the tool connect to another host with your credentials.

## 1.0.1 (2026-10-16)

### Added
- Logo: in the launcher window, as window/taskbar icon, as browser favicon and in the dashboard header; logo files and a `.ico` for shortcuts in `docs/logo`.
- Credits: the README and the script help state that the tool was developed with the assistance of Claude Code (Anthropic).
- `-NoOpen` parameter: saves the dashboard without opening the browser. Use it with `-NoGui` in scheduled tasks.
- `-OutHtml` now also works when the window is used, and creates missing folders.

### Changed
- License is now MIT with the Commons Clause: free to use, modify and share, but it may not be sold.
- Author name is now Starkark98; screenshots refreshed.
- README rewritten for GitHub (how it works, responsible use, limitations, disclaimer); added `SECURITY.md`, `CONTRIBUTING.md` and issue templates.

### Fixed
- The window failed to open when the saved "last server" file was empty.
- Unrelated server errors were reported as "DhcpServer module not found".
- If one event log could not be read, events from the other logs were hidden.
- The whole analysis failed when scope statistics could not be read.
- Open ports of excluded IPs could show as `refused,80` instead of `80`.
- Large exclusions (over 1024 IPs) were fully expanded in memory before being skipped.
- Ping objects used by the exclusion scan were not released.
- A reverse DNS error could stop the exclusion scan.
- Saving the report onto itself with "Save as..." raised an error, and errors in the window buttons could close the program.
- Unexpected errors are now shown in a message box instead of the program closing silently.
- Hostnames containing `<` can no longer break the dashboard page.

## 1.0.0

- First release.
