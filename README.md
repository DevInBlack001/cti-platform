# CTI Platform

**Shared, Trust-Checked Threat Intelligence for Institutions That Can't
Run Their Own Full Security Team**

**Author:** Abdullah Armiyao

**Project:** BSc Cybersecurity Final Year Project, Department of
Cybersecurity and Information Systems, University of Mines and Technology
(UMaT)

Terms in *italics* are defined in the [glossary](docs/glossary.md) the
first time they appear on this page.


## What It Is

Independent institutions, banks, universities, hospitals, telcos, each
run their own copy of this system (a *[node](docs/glossary.md#node)*).
Each node watches for local threats, sorts them automatically, has a
person confirm or correct that sorting, then shares the confirmed reports
with other nodes. Those other nodes decide whether to believe an incoming
report using a trust-scored voting system, which is this project's main
research contribution.

The question this project is built to answer:

> Can institutions that check each other's reports directly, instead of
> only reporting to one central authority, catch and share real threats
> more reliably than if they didn't check each other at all, and what
> does that cost in time and network traffic?

Two separate, individually defensible contributions come out of this
work:

- **Trust-checked report sharing.** Removes the single point of failure
  and bottleneck that comes with a purely centralized reporting system,
  by letting independently run institutions check each other's reports
  directly.
- **Automatic sorting of incoming reports.** Removes the bottleneck of a
  person having to sort every report by hand, without removing the
  person from the final decision. This targets a specific, confirmed gap
  in Ghana's own national incident-reporting process, where sorting is
  currently done entirely by hand with no automated help anywhere in it.

Both the sorting model and the trust-checking system were designed and
trained from scratch for this project, not adapted from something that
already existed. See [docs/architecture.md](docs/architecture.md) for
why.


## How It Is Built

This project's own five layers (collection, extraction, federation, peer
validation, local action) stand on their own; see
[docs/architecture.md](docs/architecture.md) for how they connect to
whatever local data source or downstream platform a node chooses. For
storing and browsing believed reports, this project has been testing
against **[OpenCTI](docs/glossary.md#opencti)** (Community Edition), an
external dependency it installs and talks to over its own
*[GraphQL](docs/glossary.md#graphql)* interface, never forked or
vendored in. Two original programs sit on top of this project's own
layers:

- The **trust-checking layer**, in **Rust**, for the speed and low-level
  control its networking and message-signing work benefits from.
- The **sorting model**, in **Python**, using Python's mature set of
  machine-learning tools. A
  *[gradient-boosted-trees](docs/glossary.md#gradient-boosted-trees)*
  model trained on data derived from
  [FLOD](https://github.com/DevInBlack001/ddos-reduction-system)'s
  flood-detection output.

Keeping both as separate programs, rather than editing OpenCTI itself,
keeps this project's own work clearly separate from any downstream
platform it happens to be tested against.

Full architecture, including the diagram of how a signal moves through
the system, is in [docs/architecture.md](docs/architecture.md).


## Scope

**In scope for the working prototype:** a controlled, simulated group of
4 to 8 nodes, a real (not faked) trust-scored voting mechanism, and
measured survival of three attack scenarios: one dishonest peer, one node
going offline, and a small
*[Sybil](docs/glossary.md#sybil-attack)* cluster (one attacker pretending
to be several peers).

**Out of scope:** bringing in real Ghanaian institutions, running on real
production traffic, or setting up a formal governance/legal agreement.
These belong to future work, not this deliverable.

**Explicitly not an extension of FLOD.** FLOD watches for one kind of
flood of traffic at one point in a network. This project is a
multi-institution trust-and-sharing system; what carries over from FLOD
is design experience only, not shared code or a shared research
question. See
[docs/architecture.md](docs/architecture.md#relationship-to-flod).

Full feasibility assessment, Ghana-specific context, and an honest list
of this project's limits are in
[docs/feasibility.md](docs/feasibility.md).


## Status

Implementation has started. OpenCTI (Community Edition, an external,
unforked dependency, see [docs/architecture.md](docs/architecture.md))
is deployed and running healthy in the local test VM (`deploy/`); the
local collection and extraction pipeline is spec'd and not yet built. See
[docs/ROADMAP.md](docs/ROADMAP.md) for the build order and current
phase, and [docs/lessons-learned.md](docs/lessons-learned.md) for what's
come up along the way.


## Documentation

| Document | Covers |
|-|-|
| [Architecture](docs/architecture.md) | How a signal moves through the system, the extended sorting workflow, the OpenCTI/Rust/Python split, and why the sorting model was trained rather than reused |
| [Feasibility](docs/feasibility.md) | The honest verdict on what's achievable, the test plan, the Ghana-specific gap this targets, and this project's limits |
| [Decision Record](docs/decision-record.md) | Every major design decision and the reasoning behind it, kept traceable for the final report |
| [Reading List](docs/reading-list.md) | Sources to cite, grouped by topic: standards, foundational papers, Ghana-specific sources, recent related work |
| [Roadmap](docs/ROADMAP.md) | The October to January build timeline, current phase, and what happens if the schedule slips |
| [Glossary](docs/glossary.md) | Plain-language definitions for every technical term used across these docs |
| [Lessons Learned](docs/lessons-learned.md) | Real obstacles hit during development, kept for what they generalize to |


## Authorship

This project's idea, research question, architecture, and every
functional decision originated with me, as part of my BSc Cybersecurity
final-year work at UMaT. I used AI as a planning and drafting assistant
during the feasibility, architecture, and literature-scoping work
captured in this repository's docs, and expect to use it the same way
during implementation. The decisions about what to build, why, and how
the system should behave are mine.


## Licence

See [LICENSE](LICENSE). OpenCTI is never forked, vendored, or edited by
this project, only installed and run as a separate, external dependency,
so none of its own license terms attach to this repository. See
[docs/architecture.md](docs/architecture.md#on-openctis-own-licensing)
for OpenCTI's own licensing and how this project stays clear of it.
