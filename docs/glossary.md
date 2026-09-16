# Glossary

Plain-language definitions for terms used elsewhere in these docs. Each
other document links here the first time it uses a term.

### Threat Observation

One record describing a single suspicious event (for example, "this
address sent a flood of traffic at this time"), in a shared format every
node understands.

### Node

One participating institution's own copy of the system: its own server,
its own local data, its own decision-making.

### Federation

A group of nodes (also written "federated") that cooperate and share
information without any one of them being in charge of the others.

### Peer

Another node in the federation, from the point of view of the node
currently making a decision.

### Quorum

The minimum number of independent nodes that must agree before a shared
piece of information is treated as trustworthy.

### Reputation-weighted quorum

A quorum where each node's vote counts more or less depending on how
reliable that node has been in the past, rather than every node's vote
counting the same.

### Sybil attack

One attacker pretending to be many different nodes, to make their single
opinion look like agreement from a crowd. "Sybil-lite" in these docs
means a smaller-scale version of this used for testing.

### Replay attack

Resending an old, already-seen message again later, to try to trick a
system into acting on it a second time.

### STIX

A standard, shared format for describing a threat observation (who,
what, when), so different organizations' systems can read each other's
reports without custom translation. "STIX-lite" in these docs means a
smaller version of this format, covering only the fields this project
needs.

### TAXII

A standard way of transporting STIX-formatted reports between systems
over a network. This project does not use TAXII (see
[architecture.md](architecture.md)).

### GraphQL

A way for one piece of software to ask another piece of software for
exactly the data it needs, over a network connection. It is the
interface this project's own services use to talk to OpenCTI.

### OpenCTI

An existing, open-source piece of software for storing and browsing
threat intelligence, made by a company called Filigran. This project
reuses it as its storage and display layer instead of building one from
scratch.

### MISP

A different existing open-source threat-intelligence platform,
considered as an alternative to OpenCTI before OpenCTI was chosen.

### EigenTrust

A published method for calculating how much to trust each participant in
a peer-to-peer network, based on feedback from other participants. Used
here as a reference point while designing this project's own reputation
mechanism, not used directly.

### Byzantine Fault Tolerance (BFT)

A property of a system that keeps working correctly even if some
participants are lying or broken, not just offline. Relevant if this
project's quorum mechanism needs a formal proof of how many bad nodes it
can tolerate.

### Gradient-boosted trees

A type of machine-learning model built from many small decision trees
that each correct the previous ones' mistakes. Chosen for this project's
classifier because it is fast to train and its decisions can be
inspected (see "feature importance" below).

### Feature importance

A report a machine-learning model can produce, showing which input
values mattered most to its decision. Useful for explaining why a model
flagged something.

### Kademlia

A method for nodes in a peer-to-peer network to find each other without
a central directory.

### Mutual attestation

Nodes checking each other's honesty by comparing notes, rather than
trusting each one's self-reported status.

### CERT-GH

Ghana's national Computer Emergency Response Team, the government body
incident reports ultimately flow up to.

### CSA

Ghana's Cyber Security Authority, the government agency that oversees
CERT-GH and national cybersecurity policy.

### Act 1038

Ghana's Cybersecurity Act, 2020, the law that gives the CSA its
authority and defines reporting obligations.

### Critical Information Infrastructure (CII)

The 13 sectors Act 1038 names as nationally important (banking, health,
telecoms, and so on), each with its own dedicated CERT reporting up to
CERT-GH.

### Hub-and-spoke

A reporting structure where every organization reports upward to one
central authority, and that authority is the only place information gets
compared or combined. Contrasted in these docs with a peer-to-peer
structure, where organizations can also compare notes directly with each
other.
