# Feasibility, Ghana Context, and Positioning

Terms in *italics* are defined in the [glossary](glossary.md) the first
time they appear.

## Executive verdict

A working version by end of January is realistic as a controlled,
simulated *[federation](glossary.md#federation)* of 4 to 8
*[nodes](glossary.md#node)*. "Working" means: several independent
programs, each standing in for one institution, exchanging signed
*[Threat Observations](glossary.md#threat-observation)* with each other,
running a genuinely working trust-checking step, and surviving a defined
set of attack scenarios with measured results. Bringing in real Ghanaian
institutions, running on real production traffic, or setting up a formal
governance/legal agreement between institutions are explicitly out of
scope for this milestone and belong in the report's future-work section.

The Peer Validation Layer (the part that decides whether to believe a
peer's report) is the piece most likely to threaten the timeline, since
it is the only genuinely new research problem here; everything else is
known engineering. The plan is to build a simple first version (a fixed
minimum number of confirmations needed, no trust scoring yet) so the full
pipeline runs end to end early, then add trust scoring once there is real
test data to tune it against.

## Evaluation design

Scaled down from an earlier plan (three comparison systems, 50 nodes,
seven attack scenarios) to something that fits the available time:

- **Two versions are actually built and run**: one with no trust-checking
  at all, and this project's trust-checked version. A third,
  fully-centralized comparison point exists only as a description
  grounded in existing research.
- **4 to 8 simulated nodes.** Scaling up to 50 is future work.
- **Three attack scenarios are built and tested properly**: one
  dishonest peer, one node going offline, and
  a small *[Sybil](glossary.md#sybil-attack)* cluster (one attacker
  pretending to be several peers). Two extra safeguards, replay
  protection and basic flood-rate limiting, are built into the system but
  are not each given their own dedicated test.

The full list of attack types considered, kept as-is from an earlier,
more detailed planning document: a dishonest peer, a peer that has been
taken over by an attacker, Sybil behavior, *[replay
attacks](glossary.md#replay-attack)*, flooding the system with fake
reports, a network split, and a peer simply going offline.

## Ghana relevance and the specific gap this targets

*[CERT-GH](glossary.md#cert-gh)* recorded 3,876 cybersecurity incidents
between January and July 2026, with 1,818 of them (about 47%) linked to
online fraud, according to *[CSA](glossary.md#csa)* Director-General
Divine Selase Agbeti at the September 2026 National Cyber Security
Awareness Month launch. A separate disclosure in September 2025 reported
that login credentials belonging to 35 organizations, including
ministries, banks, hospitals, and universities, had surfaced on the dark
web, a concrete example of the kind of exposure across many institutions
this project's design is meant to help with.

Ghana has named 13 *[Critical Information
Infrastructure](glossary.md#critical-information-infrastructure-cii)*
sectors under *[Act 1038](glossary.md#act-1038)* (sections 35 to 40,
Gazette Notice 132), each with its own sector-level CERT reporting up to
CERT-GH. That existing structure is exactly the gap this project targets:
the sectors already have a place to report to, but there is no proven way
for sector CERTs to check reports against each other directly. Right now
the setup is *[hub-and-spoke](glossary.md#hub-and-spoke)*: individual
organizations and their sector CERTs report upward to CERT-GH, and
CERT-GH sends advisories back out, with nothing built for sector CERTs to
compare notes with each other along the way.

Two further facts, confirmed through research, matter for this project's
second contribution (automated classification):

- **Ghana's current national process is confirmed hub-and-spoke, not
  peer-to-peer.** There is no described way for sectors or organizations
  to check or confirm threat reports directly with each other.
- **CERT-GH's own triage step is confirmed to be done entirely by hand.**
  Incidents come in by web form, email, phone, SMS, WhatsApp, or a mobile
  app, and are then prioritized and assigned by a human analyst, with no
  sign of automated sorting anywhere in that process. This is exactly the
  gap this project's second contribution, an automated classifier that
  assists that human step, is built to help with: a real, documented
  bottleneck.

## A clear line on what this project claims

Act 1038 gives the CSA a centralized reporting role. This project is
described throughout as something that helps institutions act on threat
intelligence faster than a purely centralized channel allows, while still
sending believed reports upward to CERT-GH, working alongside that
centralized role. Leaving this unstated would
risk an examiner reading the project as trying to bypass national
cybersecurity governance, which is not the intent.

## Honest limitations

The evaluation described above is a controlled test among simulated
nodes. It shows that this project's trust-checking approach can resist a
defined set of attacks with measurable tradeoffs. It does not show that
real Ghanaian institutions would actually adopt it, that it would work
alongside CSA's existing reporting channel in practice, or that it would
hold up against real attackers. This limitation is stated plainly here,
since claiming
this semester-scale prototype is "a solution for Ghana's cybersecurity
problem" is exactly the kind of overreach an examiner is likely to
challenge.

## Project selection

Two candidate final-year project ideas were compared: this one (shared,
trust-checked threat intelligence between institutions) against a
separate idea for secure file-sharing between peers. This one was chosen
for three reasons: it fits squarely within cybersecurity/trust research,
which matters for how a department committee will judge it; its core
question, "why should one node believe another node's report," is narrow
and measurable; and an already-designed but unbuilt piece of prior work,
a
peer-to-peer network design using
*[Kademlia](glossary.md#kademlia)*-based discovery and
*[mutual attestation](glossary.md#mutual-attestation)*, applies directly
to this project's hardest problem, the Peer Validation Layer.
