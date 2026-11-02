# Previous plan superseded

The original watchdog repair plan has been retired in version 2. Its
movie-definition-table diagnosis was incorrect: the affected insertion routine
belongs to the archive resource name index. The old remote chain edit and forced
lock reset did not establish that the resulting index preserved its contents.
They are no longer part of the plugin.

The historical captures support investigating a real insertion loop and blocked
resource readers. They do not identify the original cause of the damaged table,
prove that F4SE caused it, or validate the replacement implementation. A reported
successful load with the old build is not a save-safety result for version 2.

Current documentation:

- [README](README.md): supported profile, build, configuration, and controlled testing.
- [Engine contract](docs/engine-contract.md): recovered native semantics, identity
  hashes, guarded rebuild, and declined states.
- [Validation record](docs/validation.md): reproducible tests, completed Windows
  checks, and the in-game validation still required.

The previous plan remains available in Git history as historical material, not
as the specification for the current code.
