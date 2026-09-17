# Security Policy

## What this project is

A BSc Cybersecurity final-year project at UMaT, a research prototype
built to answer one research question within a single academic term,
not a maintained product with a support contract. See
[README.md](README.md) and
[docs/feasibility.md](docs/feasibility.md) for the full scope and its
honest limitations.

That said, the code here handles real signing keys, real credentials
(via environment variables, never hardcoded), and talks to real
external systems (OpenCTI, Wazuh), so a genuine security report is
taken seriously and worth reporting properly.


## Supported versions

Only the latest commit on `master` gets fixes. There are no released,
versioned builds yet; see [docs/ROADMAP.md](docs/ROADMAP.md) for the
current build phase.


## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository
(the "Report a vulnerability" button under the repo's Security tab)
so a real issue isn't publicly visible before a fix lands. If that
option isn't available, open a regular
[issue](https://github.com/DevInBlack001/cti-platform/issues)
describing the class of problem without exploit details, and a
private channel can be arranged from there.

Include what's actually needed to reproduce and assess it: the
affected file/function, the input or configuration that triggers it,
and what the impact is. A report against a specific commit hash is
more useful than one against "the repo" generally, since this project
moves quickly.


## Scope

**In scope**: this repository's own code, everything under
`collection/`, `deploy/`, and `scripts/`.

**Out of scope**: OpenCTI's own code and the OpenCTI Community Edition
platform itself, this project only installs and configures it (see
[docs/decision-record.md](docs/decision-record.md) for why). Report
issues in OpenCTI itself to
[Filigran](https://github.com/OpenCTI-Platform/opencti). Report issues
in Wazuh itself to its own upstream project the same way.


## Findings already reviewed and addressed

This project runs a real security review as an ongoing part of its own
development process. Real findings caught and fixed along the way,
including a SQLite URI injection, an unguarded sink file, a STIX
pattern injection, and several deployment-configuration exposures, are
recorded in [docs/lessons-learned.md](docs/lessons-learned.md) and
[docs/decision-record.md](docs/decision-record.md), kept in place as
an honest record once fixed.


## Deliberate, documented exceptions

Two settings intentionally weaken a default security posture, both off
by default and named to make that unmistakable:

- **`CTI_ALLOW_INSECURE_TLS`** disables TLS certificate verification
  for the OpenCTI and Wazuh connectors. Meant for development against
  a self-signed test server only. Emits a runtime warning every time
  it's active.
- **`OPENCTI_ACKNOWLEDGE_HTTP_EXPOSURE`** lets `deploy/`'s startup
  check proceed with `OPENCTI_BIND_ADDRESS` widened beyond its
  loopback default while still on plaintext HTTP, for a deployment
  confined to a trusted, already-isolated network (this project's own
  QEMU test VM, reachable only through its own host-only port
  forward). Requires the operator to have already widened the bind
  address deliberately before this does anything at all.

A report that one of these settings does what its own name and
documentation say it does, once explicitly enabled, isn't a new
finding, both are already reviewed and accepted as intentional. A
report that either one can be triggered without that explicit,
documented opt-in is a real finding and welcome.
