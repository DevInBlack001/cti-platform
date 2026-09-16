# Feasibility, Ghana Context, and Positioning

## Executive verdict

A working version by end of January is achievable if scoped as a
controlled, simulated federation of 4 to 8 nodes, not a real
multi-institution pilot. A "working version" means: several independent
processes, each representing an institution's node, exchanging signed
threat observations over a federation layer, running a real (not stubbed)
peer-validation mechanism, and surviving defined adversarial scenarios with
measured results. Onboarding actual Ghanaian institutions, running on real
production traffic, or having a governance/legal framework in place are
explicitly out of scope and belong in the report's future-work section.

The Peer Validation Layer is the component most likely to threaten the
timeline, since it is the only part of the system that is genuinely novel
research rather than known engineering. The plan is to build a deliberately
naive version first (fixed quorum threshold, no reputation weighting) so
the full pipeline runs end to end early, then layer reputation weighting on
top once real experimental data exists to justify tuning it.

## Evaluation design

Scoped down from an initial three-baseline, 50-node, seven-scenario plan to
something achievable in the available time:

- **Two live tiers** are built and run: a no-validation gossip baseline,
  and the validated peer-assisted system. A third, purely centralized model
  is described analytically using established literature rather than built
  as a third running system.
- **4 to 8 simulated nodes.** Scaling to 50 nodes is future work, not built.
- **Three threat scenarios built and evaluated well**, rather than seven
  built shallowly: a single malicious peer, node failure, and a Sybil-lite
  cluster of fake identities from one attacker. Replay protection and basic
  flood-rate-limiting are implemented as engineered mitigations within the
  system but are not each given a dedicated experiment.

The full threat model, adopted as-is from an earlier, more detailed
proposal document: malicious peer, compromised peer, Sybil behaviour,
replay attack, intelligence flooding, network partition, and plain peer
failure.

## Ghana relevance and the specific structural gap

CERT-GH recorded 3,876 cybersecurity incidents between January and July
2026, with 1,818 (approximately 47%) linked to online fraud, disclosed by
CSA Director-General Divine Selase Agbeti at the September 2026 National
Cyber Security Awareness Month launch. A separate disclosure in September
2025 reported credentials belonging to 35 organizations, including
ministries, banks, hospitals, and universities, surfacing on the dark web,
a concrete example of the cross-sector exposure this project's architecture
is meant to address.

Ghana has 13 designated Critical Information Infrastructure sectors under
the Cybersecurity Act, 2020 (Act 1038, sections 35 to 40, Gazette Notice
132), each coordinated by its own sector-level CERT under CERT-GH. This
existing structure is the specific gap this project targets: the
scaffolding for sector-level coordination already exists, but there is no
validated peer-to-peer exchange mechanism between sector-CERTs, only a
hub-and-spoke model where individual organizations and sectoral CSIRTs
report upward to CERT-GH, and CERT-GH issues advisories back out.

Two further structural facts, confirmed by research, are directly relevant
to Contribution B (automated classification):

- **CSA's current model is confirmed hub-and-spoke, not peer-to-peer.** No
  described mechanism exists for sectors or organizations to corroborate or
  validate threat indicators directly with each other.
- **CERT-GH's triage is confirmed manual and human-driven.** Incident
  intake, via web form, email, phone, SMS, WhatsApp, or a mobile app,
  funnels to human analysts who prioritize each report and assign an
  incident handler, with no evidence of automated classification anywhere
  in that process. This confirms the value of Contribution B: an automated
  classifier assisting (not replacing) that human triage step removes a
  genuine, documented speed bottleneck, rather than solving a problem that
  was already automated elsewhere.

## Explicit positioning requirement

Act 1038 gives the CSA a centralized incident-reporting mandate. The system
is framed throughout as complementary to this mandate, letting
resource-constrained institutions validate and act on threat intelligence
faster than a purely centralized channel allows, while still feeding
validated indicators upward to CERT-GH, not as a parallel or bypass
mechanism. Left implicit, this risks being misread by an examiner as
proposing to circumvent national cybersecurity governance, which is not the
intent.

## Honest limitations

The evaluation is a controlled simulation among synthetic nodes. It
demonstrates that the peer-assisted validation mechanism can resist a
defined set of adversarial scenarios with measurable tradeoffs. It does not
demonstrate that Ghanaian institutions would adopt it, that it
interoperates with CSA's existing reporting channel in practice, or that it
holds up against real adversaries rather than simulated ones. This boundary
is stated explicitly rather than left implicit, since overclaiming "a
solution for Ghana's cybersecurity problem" from a semester-scale prototype
is the kind of statement an examiner will specifically probe.

## Project selection

Two candidate final-year projects were compared: this one (peer-assisted
federated threat intelligence sharing) against a secure peer-assisted
content distribution system. This one was chosen for three reasons: it
sits squarely inside cybersecurity/trust research rather than drifting into
general distributed-systems territory, which matters for how a department
committee evaluates it; the research problem (why should Node B believe
Node A's report) is tightly scoped and measurable, unlike the alternative's
broader and less bounded research questions; and an existing unbuilt
design, a decentralized P2P overlay network (Kademlia-based peer discovery,
mutual attestation, peer ejection), transfers directly onto this project's
hardest problem, the peer validation layer.
