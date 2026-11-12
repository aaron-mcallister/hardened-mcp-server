# Security policy

This is a personal reference project, not a product, and carries no support commitment. If you find a vulnerability in the code, please report it privately through GitHub's "Report a vulnerability" (private vulnerability reporting) on this repository rather than a public issue. You will get a best-effort response.

Reports about the *tests failing to notice a broken control* are especially welcome: the point of this repository is that every security claim in `docs/THREAT-MODEL.md` is backed by a test that would fail if the control were removed.

The fixture data is fictional. The "attacker" strings in the test data point at `attacker.example`, a reserved name that is never contacted.
