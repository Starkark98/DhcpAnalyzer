# Changelog

## 1.0.1 (2026-10-15)

### Added
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
