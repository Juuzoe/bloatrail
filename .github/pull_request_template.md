<!--
CONTRIBUTING.md has the detail: the rules a detector follows, the tests one
needs, and what changing cleanup safety or JSON output involves.
Delete whatever does not apply.
-->

## What this changes

<!-- One or two sentences. What is different after this, and why. -->

## How it was checked

- [ ] `cargo test --all-targets`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] Tried against a real directory, not only the fixtures

<!-- If this adds or changes a detector, paste the before and after of
     `bloatrail explain <path>` on a directory it affects. -->

## Safety

<!-- Only if this touches classification or cleanup. -->

- [ ] Nothing newly classified `SAFE` unless a build tool can recreate it
- [ ] The detector fires on project evidence, not on the directory name alone
- [ ] There is a test proving it does *not* fire when that evidence is absent
