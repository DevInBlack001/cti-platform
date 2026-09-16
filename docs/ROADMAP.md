# Roadmap

Timeline: October 2026 to end of January 2027 (about 17 weeks), covering
everything needed for a working prototype milestone. Full reasoning behind
scope and cuts is in [feasibility.md](feasibility.md). Terms in *italics*
are defined in the [glossary](glossary.md) the first time they appear.


## Completed

**Phase 0: Planning and feasibility (September 2026).**

- Research question scoped and finalized.
- Five-layer core architecture defined, extended with the automated
  classification workflow.
- Platform and language choices locked in: OpenCTI (an external,
  unforked dependency) as the sink this project tests against, Rust for
  the peer validation layer, Python for the classifier.
- Evaluation design scoped down to something achievable in the timeline:
  two live tiers, 4 to 8 simulated nodes, three threat scenarios.
- Ghana context researched and confirmed: CSA's model is hub-and-spoke,
  not peer-to-peer; CERT-GH's triage is manual, with no automated
  classification step.
- Reading list and citation resources gathered by category.
- Full decision record written; see [decision-record.md](decision-record.md).

**Phase 0.5: OpenCTI stood up (September 2026), ahead of the original timeline.**

Not originally scheduled as its own step (see
[decision-record.md](decision-record.md) for that gap and why it got
closed here rather than left implicit). OpenCTI is deployed inside the
local test VM, as an external, unforked Community Edition install, and
running healthy end to end (platform, worker, and the standard
connectors, all confirmed reachable over HTTP). See
[lessons-learned.md](lessons-learned.md) for what it took to get there,
and [decision-record.md](decision-record.md) for the later decision to
drop an earlier fork of OpenCTI's repository once discovered to carry
a separate, more restrictive license.

**Phase 1: Local Collection Layer built and tested (September 2026), ahead of the original schedule.**

Originally scheduled for weeks 3-4 (see the Planned table below); built
early in the same stretch of work as Phase 0.5, using
subagent-driven-development with a fresh implementer and an independent
task review for each of 9 tasks, plus a dedicated security review and a
final whole-branch review before merging. The `collection/` Python
package reads a FLOD-shaped *[source connector](glossary.md#source-connector)*,
builds and Ed25519-signs a *[Threat Observation](glossary.md#threat-observation)*
per detection, and appends it to a local file, no network code, matching
the milestone's own scope. Verified against a test fixture (48 automated
tests) and separately against a real copy of FLOD's live database pulled
from the test VM: 40,510 real detection rows processed, every resulting
signature independently verified. See
[decision-record.md](decision-record.md) for the security findings this
review caught and fixed before merge.


## Planned

| Weeks | Dates (approx.) | Focus | Deliverable |
|---|---|---|---|
| 1 | Oct 1-7 | Targeted literature scan (10-12 sources). Finalize research question and threat scenarios. | Research question, 1-page problem statement |
| 2 | Oct 8-14 | Finalize architecture. Commit to the trust-checking mechanism (a *[reputation-weighted quorum](glossary.md#reputation-weighted-quorum)*). | Architecture doc + Threat Observation schema |
| 3-4 | Oct 15-28 | *(Completed early, see Phase 1 above.)* Build Local Collection + Intelligence Extraction layers; wire in FLOD output as a real data source. | Working single-node pipeline: raw signal to signed observation |
| 5-6 | Oct 29-Nov 11 | Build the Federation Layer: peer identity, discovery, signed message exchange over the network. | 2 nodes exchanging signed observations |
| 7-8 | Nov 12-25 | Build Peer Validation Layer v1 (naive fixed quorum, no reputation yet). Full pipeline running end to end across 4 nodes. | 4-node simulation, functioning end to end |
| 9 | Nov 26-Dec 2 | Build Local Action / policy layer. Add reputation scoring on top of the naive quorum (v2). | Reputation-weighted validation |
| 10 | Dec 3-9 | Instrumentation: logging, metrics (propagation latency, false-accept/reject rate, bandwidth). Build the minimalist per-node dashboard: reputation scores, quorum decisions, and attack-scenario results, with an outbound link to the node's own CTI platform for full browsing. | Measurement harness ready; node dashboard live |
| 11-12 | Dec 10-23 | Run honest-propagation and node-failure experiments. Reduced-capacity window, treated as buffer. | Baseline results |
| - | Dec 24-Jan 1 | Deliberate low-output period. | - |
| 13-14 | Jan 2-15 | Run the dishonest-peer and *[Sybil](glossary.md#sybil-attack)*-lite experiments, where the actual research finding is expected to emerge. Likely one iteration of the trust-checking mechanism based on what breaks. | Adversarial results, at least one documented failure mode |
| 15 | Jan 16-22 | Analyze results, tie findings back to literature, refine if time allows. | Results section draft |
| 16-17 | Jan 23-31 | Polish, demo prep, write-up of the working-version milestone. | Working prototype + written progress report |

**If behind schedule by week 10:** cut indicator-type breadth first, then
cut the node-failure experiment before cutting the malicious-peer or
Sybil-lite experiments. The adversarial results are the actual
contribution; failure-tolerance is comparatively well-trodden ground in
the literature.


## Explicitly future work, not on this roadmap

- Onboarding real Ghanaian institutions as pilot nodes.
- Running on real production traffic rather than simulated/synthetic data.
- A governance or legal framework for cross-institution sharing.
- Scaling the federation beyond 8 simulated nodes.
- Building out the remaining four threat scenarios from the full threat
  model (compromised peer, replay attack, intelligence flooding, network
  partition) as dedicated experiments, rather than engineered mitigations
  without their own measurement.
- Additional indicator types beyond DDoS, beyond the synthetic/sample data
  used to demonstrate the architecture generalizes.
- Building real source and sink connectors for tools beyond FLOD and
  OpenCTI, once an institution actually needs one. The
  brute-force scenario's own detector is real, live-simulated traffic in
  the VM testbed, the same pattern as DDoS; the phishing scenario stays
  sample data, generated fresh by a script every time it's needed, never
  a static fixture file, since full phishing infrastructure is
  disproportionate cost for this milestone.
- A future sink connector layer that fans out to multiple sinks at once,
  a node's downstream CTI platform (or several) and its peers over the
  federation layer, simultaneously, not one active sink at a time.
