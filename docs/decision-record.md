# Decision Record

A chronological record of the major decisions made across planning, kept
here so the reasoning behind each is traceable in the final report rather
than presented as an unexplained given. Terms in *italics* are defined in
the [glossary](glossary.md) the first time they appear.

| Decision | Reasoning |
|---|---|
| This project chosen over a peer-to-peer file-sharing alternative | A tighter fit for a cybersecurity department; a narrower, more measurable research question; an already-designed peer-to-peer network layout carries over directly onto the hardest part of this project. |
| Explicitly not treated as an extension of FLOD | FLOD watches for one kind of attack at one point in a network; this project is about trust between many institutions. Only the habit of keeping "what was detected" separate from "what to do about it" carries over. |
| Test plan scaled down from 3 comparison systems / 50 nodes / 7 attack scenarios to 2 working systems / 4 to 8 nodes / 3 attack scenarios | Fits an October to January timeline; the original plan was closer to 6 to 12 months of work. |
| A second contribution (automated classification) added alongside trust-checking | Research confirmed CERT-GH's own sorting step is done entirely by hand, with no automated help anywhere in it, a real, documented gap rather than something already solved elsewhere. |
| VLAI (an existing pretrained severity-scoring model) not used as the classifier's starting point | Two reasons together: VLAI is trained on vulnerability-description text, a different kind of input from the traffic and log data this project classifies, so it would not have worked; and training a new model from labeled data built specifically for this project makes the contribution clearly original work. |
| Classifier built as a self-trained *[gradient-boosted-trees](glossary.md#gradient-boosted-trees)* model over a small set of hand-picked measurements, not a large from-scratch deep-learning model | Matches the realistic amount of training data available and the project timeline; trains quickly enough to iterate on; and its decisions can be inspected, which helps both the write-up and a reviewer's trust in a given result. |
| *[OpenCTI](glossary.md#opencti)* reused as the storage/display platform, rather than building one from scratch | Keeps the limited build time focused on this project's two genuinely new pieces; OpenCTI is actively maintained and its license allows reuse with clear rules for what crediting is required. |
| OpenCTI compared against *[MISP](glossary.md#misp)* before choosing | MISP's way of recording independent sightings of the same indicator, and its built-in message signing, were noted as useful reference points, but OpenCTI's more active development and its way of storing relationships between records made it the better fit. |
| The Peer Validation Layer and the classifier built as their own separate programs calling OpenCTI, rather than edited into OpenCTI itself | Keeps this project's own original work clearly separate from the reused platform, both for license clarity and for how the work will be examined. |
| Rust chosen for the Peer Validation Layer; Python chosen for the classifier | Rust's speed and low-level control suit the networking and message-signing work; Python's mature machine-learning tools suit the classifier. Neither sits inside OpenCTI's own code, which is written in TypeScript/JavaScript with some Python and Node used for its own connectors. |
| Reading and gathering citations left until closer to report-writing time, not treated as something that had to happen before any code could be written | Matches an established working pattern of building first and reading deeply right before the sections that need those citations; the design and feasibility groundwork was already complete. |
