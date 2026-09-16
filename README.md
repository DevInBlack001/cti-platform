# CTI Platform

**Peer-Assisted Federated Threat Intelligence Sharing for
Resource-Constrained Institutions**

**Author:** Abdullah Armiyao

**Project:** BSc Cybersecurity Final Year Project, Department of
Cybersecurity and Information Systems, University of Mines and Technology
(UMaT)


## What It Is

Independent institutions (banks, universities, hospitals, telcos) each run
a node that collects local threat signals, classifies them automatically,
has a human analyst confirm or override that classification, then shares
validated observations with peer nodes. Peers decide whether to trust an
incoming observation using a reputation-weighted quorum mechanism, the
actual research contribution of the project.

The research question it is built to answer:

> Can a peer-assisted federation validate and propagate threat intelligence
> across independently operated, resource-constrained nodes with measurably
> better resilience to false or malicious reports than naive/no validation,
> and at what cost in propagation latency and bandwidth?

Two separately defensible contributions come out of this:

- **Peer validation layer.** Removes the single point of failure and
  central-queue bottleneck inherent in a purely centralized reporting
  model, via reputation-weighted quorum validation between independently
  operated nodes.
- **Automated severity/validity classification.** Removes the human-speed
  bottleneck in triage at each node, without removing the human from the
  final decision. This targets a specific, confirmed gap in Ghana's
  existing national incident-reporting process: CERT-GH's triage is
  currently manual and human-driven, with no automated classification
  step anywhere in it.

Both the classifier and the peer validation layer are self-designed and
self-trained, not adapted from an existing pretrained model. See
[docs/architecture.md](docs/architecture.md) for why.


## How It Is Built

**OpenCTI** (Community Edition, Apache 2.0) is forked, left otherwise
unmodified, and used as the storage, data-model, and UI backbone. Two
original services sit on top of it and talk to it over its GraphQL API:

- The **peer validation layer**, in **Rust**, for the performance and
  low-level control its networking and cryptographic work benefits from.
- The **classifier**, in **Python**, using Python's mature ML tooling. A
  gradient-boosted-trees model over hand-engineered traffic features,
  trained on labeled data derived from
  [FLOD](https://github.com/DevInBlack001/ddos-reduction-system)'s DDoS
  detection output.

Keeping both as separate services rather than modifying OpenCTI's
internals keeps this project's own contributions cleanly separated from
the forked codebase, both for licensing clarity and for how the work is
examined.

Full architecture, including the five-layer pipeline and the extended
classification workflow, is in [docs/architecture.md](docs/architecture.md).


## Scope

**In scope for the working prototype:** a controlled, simulated federation
of 4 to 8 nodes, a real (not stubbed) reputation-weighted quorum validation
mechanism, and measured survival of three adversarial scenarios: a single
malicious peer, node failure, and a Sybil-lite cluster of fake identities
from one attacker.

**Out of scope:** onboarding actual Ghanaian institutions, running on real
production traffic, or having a governance/legal framework in place. These
belong to future work, not the deliverable.

**Explicitly not an extension of FLOD.** FLOD detects and mitigates one
DDoS indicator type at one gateway. This project is a multi-institution
trust and validation platform; what carries over from FLOD is design
experience only, not shared code or a shared research question. See
[docs/architecture.md](docs/architecture.md#relationship-to-flod).

Full feasibility assessment, Ghana positioning, and honest limitations are
in [docs/feasibility.md](docs/feasibility.md).


## Status

Planning and design stage. The architecture, evaluation design, and
technology choices are settled (see the [decision
record](docs/decision-record.md)); implementation has not started. See
[ROADMAP.md](ROADMAP.md) for the build order and current phase.


## Documentation

| Document | Covers |
|-|-|
| [Architecture](docs/architecture.md) | The five-layer pipeline, the extended classification workflow, the OpenCTI/Rust/Python split, and why the classifier is trained rather than forked |
| [Feasibility](docs/feasibility.md) | Executive verdict, evaluation design, the Ghana structural gap this targets, and honest limitations |
| [Decision Record](docs/decision-record.md) | Every major design decision and the reasoning behind it, kept traceable for the final report |
| [Reading List](docs/reading-list.md) | Citation resources by category: standards, foundational papers, Ghana-specific sources, recent related work |
| [Roadmap](ROADMAP.md) | The October to January build timeline, current phase, and what happens if the schedule slips |


## Authorship

This project's concept, research question, architecture, and every
functional decision originated with me, as part of my BSc Cybersecurity
final-year work at UMaT. I used AI as a planning and drafting assistant
during the feasibility, architecture, and literature-scoping work captured
in this repository's docs, and expect to use it the same way during
implementation. The decisions about what to build, why, and how the system
should behave are mine.


## Licence

See [LICENSE](LICENSE). Note that any OpenCTI source file this project
directly modifies, once the fork is vendored in, must keep OpenCTI's
existing license headers and carry a prominent notice stating what
changed, per OpenCTI's own Apache 2.0 terms.
