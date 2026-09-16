# Roadmap

Timeline: October 2026 to end of January 2027 (about 17 weeks), covering
everything needed for a working prototype milestone. Full reasoning behind
scope and cuts is in [feasibility.md](feasibility.md).


## Completed

**Phase 0: Planning and feasibility (September 2026).**

- Research question scoped and finalized.
- Five-layer core architecture defined, extended with the automated
  classification workflow.
- Platform and language choices locked in: OpenCTI fork as the backbone,
  Rust for the peer validation layer, Python for the classifier.
- Evaluation design scoped down to something achievable in the timeline:
  two live tiers, 4 to 8 simulated nodes, three threat scenarios.
- Ghana context researched and confirmed: CSA's model is hub-and-spoke,
  not peer-to-peer; CERT-GH's triage is manual, with no automated
  classification step.
- Reading list and citation resources gathered by category.
- Full decision record written; see [decision-record.md](decision-record.md).


## Planned

| Weeks | Dates (approx.) | Focus | Deliverable |
|---|---|---|---|
| 1 | Oct 1-7 | Targeted literature scan (10-12 sources). Finalize research question and threat scenarios. | Research question, 1-page problem statement |
| 2 | Oct 8-14 | Finalize architecture. Commit to the validation mechanism (reputation + quorum hybrid). | Architecture doc + Threat Observation schema |
| 3-4 | Oct 15-28 | Build Local Collection + Intelligence Extraction layers; wire in FLOD output as a real data source. | Working single-node pipeline: raw signal to signed observation |
| 5-6 | Oct 29-Nov 11 | Build the Federation Layer: peer identity, discovery, signed message exchange over the network. | 2 nodes exchanging signed observations |
| 7-8 | Nov 12-25 | Build Peer Validation Layer v1 (naive fixed quorum, no reputation yet). Full pipeline running end to end across 4 nodes. | 4-node simulation, functioning end to end |
| 9 | Nov 26-Dec 2 | Build Local Action / policy layer. Add reputation scoring on top of the naive quorum (v2). | Reputation-weighted validation |
| 10 | Dec 3-9 | Instrumentation: logging, metrics (propagation latency, false-accept/reject rate, bandwidth). | Measurement harness ready |
| 11-12 | Dec 10-23 | Run honest-propagation and node-failure experiments. Reduced-capacity window, treated as buffer. | Baseline results |
| - | Dec 24-Jan 1 | Deliberate low-output period. | - |
| 13-14 | Jan 2-15 | Run malicious-peer and Sybil-lite experiments, where the actual research finding is expected to emerge. Likely one iteration of the validation mechanism based on what breaks. | Adversarial results, at least one documented failure mode |
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
