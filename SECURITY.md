# Security policy

## Reporting a vulnerability

Report it privately through GitHub, at
[Security → Report a vulnerability](https://github.com/Juuzoe/bloatrail/security/advisories/new).
That opens a draft advisory only you and the maintainer can read.

Please do not open a public issue for anything in the list below until there
has been a chance to fix it.

You can expect an acknowledgement within a week. If a report is confirmed, the
fix ships in the next release and the advisory is published with credit, unless
you would rather not be named.

## What counts

Bloatrail deletes files. That makes a handful of ordinary-looking bugs into
security bugs, and these are the ones worth reporting privately:

- **A wrong `SAFE` verdict.** Anything that gets non-regenerable data
  classified as safe to remove — a marker file that can be planted to make an
  unrelated directory look like build output, a detector that fires on the
  directory name without the project evidence behind it, a classification that
  survives when it should be downgraded.
- **Escaping the cleanup scope.** A symlink, junction, hardlink or reparse
  point that makes `clean` remove something outside the path it was given. The
  same for a path that walks upward out of the scan root.
- **A confirmation that does not describe what happens.** The dialog and the
  dry run are the safety mechanism; a case where the plan shown and the plan
  executed differ is a security bug, not a display bug.
- **Install script verification.** `install.sh` and `install.ps1` fetch an
  archive and check it against `SHA256SUMS` before writing anything. Any way to
  get an unverified or substituted archive past that check, or to make the
  scripts write outside the install directory.
- **Privilege or path handling on any platform**, including Windows drive and
  UNC path parsing, and anything that makes the tool act on a path the user did
  not name.

## What does not

- Bloatrail reporting a size you disagree with, or declining to classify
  something. Those are [ordinary issues](https://github.com/Juuzoe/bloatrail/issues/new/choose).
- Deleting something you told it to delete. `clean` states its plan, defaults
  to a dry run, and the desktop app sends removals to the Recycle Bin. Choosing
  to remove a directory it marked `REVIEW` is the documented behaviour.
- Vulnerabilities in a dependency with no path to exploit through Bloatrail.
  Report those upstream; if there is a reachable path here, that is in scope.

## Supported versions

Fixes go to the latest release. There are no maintained release branches, so
if you are on an older version the upgrade is the fix.
