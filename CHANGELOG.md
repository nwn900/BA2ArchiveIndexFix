# Changelog

## 2.1.5

- Write a commented `BA2ArchiveIndexFix.ini` on first run when none exists. An existing
  file is never overwritten.

## 2.1.4

- Treat an unrecoverable partial installation as a startup-blocking failure: log
  the residual count, show a message box, and terminate before gameplay.

## 2.1.3

- Report a partial installation explicitly instead of claiming the engine is
  unmodified.
- Document the zero-key fallback as a degradation, not safe recovery.

## 2.1.2

- Commit the native corrections last, so a later failure cannot leave the engine
  patched while the log reports INERT.
- Return a deterministic zero key instead of the key-array base when the extended
  vector cannot be validated.

## 2.1.1

- Never free a stub whose patch could not be rolled back.
- Report `all_or_nothing` instead of `atomic`.

## 2.1.0

Extended archive storage is now supported when Daytripper4 is installed.

- Reads archive keys 0-254 from the fixed array and 255 and above from
  Daytripper's `std::vector<ResourceID>`, then rebuilds the table from the real
  keys. Earlier versions declined every index at or above 255.
- Corrects the engine's collision-loop key read (`archive_lookup+0xBB`) so every
  chain member is compared against its real key. Previously an extended member in
  a collision chain could not be retrieved.
- Corrects the engine's two insertion key reads (`archive_insert+0x25` and
  `+0xA2`) so the native insert hashes the real key. Previously it corrupted the
  chain on the first extended insertion, which is why the rebuild ran repeatedly.
- The corrections are installed only when the reviewed Daytripper detours are
  detected and the normalized routine hashes match. Without them the plugin
  behaves as before and the stock engine path is untouched.
- Logs `native corrections lookup_loop=… insert_incoming=… insert_displaced=…`.

## 2.0.3

- Read extended archive keys through the verified vector layout.
- Gate the key reader on the extended-storage contract so a native 255-member
  table is not mistaken for a vector.

## 2.0.2

- Diagnostics only: report an unavailable capacity separately from a raw header
  observation, sample repetitive declines, and state `extended_storage_repair=0`.

## 2.0.1

- Accept verified Daytripper accessor detours and explain identity mismatches.

## 2.0.0

- Replace the watchdog workaround with a validated rebuild on the engine's own
  writer thread.
