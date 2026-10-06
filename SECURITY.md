# Security policy

cb exists to keep real credentials away from developer machines, so we take security reports seriously.
Thank you for helping keep cb and its users safe.

## Report a vulnerability

Report it privately through GitHub:

**[https://github.com/gdhyani/cb-backend/security/advisories/new](https://github.com/gdhyani/cb-backend/security/advisories/new)**

- **Do not open a public issue, discussion or pull request** for a vulnerability.
- **Never include real secrets, tokens or customer data** in a report. Use stand-in values
  (for example `sk_test_cb…` or `cbu_ab12cd34`) and describe where the real value would appear.
- Include what you found, the steps to reproduce it, the affected version or commit, and the impact you expect.

If the issue affects another cb repository as well, report it in the one you think is most affected;
we coordinate the fix across repositories.

## What to expect

- We aim to acknowledge your report within **3 working days**.
- We keep you updated while we investigate and fix it, and agree with you on when to publish.
- We credit you in the advisory unless you ask us not to.

## Supported versions

cb is pre-1.0. Security fixes land on the latest `main` only; there are no maintained release branches yet.

| Version | Supported |
|---|---|
| latest `main` | Yes |
| anything older | No |
