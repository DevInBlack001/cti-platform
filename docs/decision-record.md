# Decision Record

A chronological record of the major decisions made across planning, kept
here so the reasoning behind each is traceable in the final report rather
than presented as an unexplained given.

| Decision | Reasoning |
|---|---|
| Project chosen over the peer-assisted content distribution alternative | Tighter security-research fit for the department; a clearer, more bounded research question; the existing unbuilt P2P overlay design transfers directly onto the hardest sub-problem. |
| Explicitly not framed as a FLOD extension | FLOD covers one indicator type at one gateway; this project is multi-institution trust research. Only design experience (tiered enforcement, separating verdict from policy) transfers. |
| Evaluation scope reduced from 3 baselines / 50 nodes / 7 scenarios to 2 live tiers / 4 to 8 nodes / 3 scenarios | Matches an October to January timeline; the full original scope was closer to a 6 to 12 month research build. |
| A second contribution (automated classification) added alongside peer validation | Confirmed via research that CERT-GH's triage is manual and human-driven with no automated classification step, a real, documented gap rather than a redundant solve. |
| VLAI (pretrained severity classifier) rejected as the classifier's basis | Two independent reasons converge: VLAI is trained on CVE/vulnerability text, a different input domain from DDoS/phishing/brute-force signals, so it would not have worked technically; and the classifier needed to be self-trained on self-labeled data to be defensibly original work. |
| Classifier built as a self-trained gradient-boosted-trees model on hand-engineered features, not a from-scratch transformer | Realistic given available data volume and timeline; trains fast enough to iterate within the schedule; produces inspectable feature importances useful for both the evaluation section and analyst trust. |
| OpenCTI forked as the platform base, rather than building a platform from scratch | Keeps build time focused on the two genuinely novel contributions; OpenCTI is mature, actively maintained, and Apache 2.0 licensed, which permits forking and modification with straightforward attribution obligations. |
| OpenCTI evaluated against MISP before choosing | MISP's sighting-support and built-in signing were reviewed as relevant reference points, but OpenCTI's more actively maintained, graph-oriented data model was judged the better platform to extend. |
| Peer validation layer and classifier built as separate services calling OpenCTI's GraphQL API, rather than modifying OpenCTI's internals | Keeps the project's own original contributions cleanly separated from the forked codebase, both for licensing clarity and for how the work is presented and examined. |
| Rust chosen for the peer validation layer; Python chosen for the classifier | Performance and low-level control for the networking/cryptographic peer-validation work; mature ML tooling for the classifier. Neither language lives inside OpenCTI's own codebase, which is TypeScript/JavaScript with Python and Node used for connectors. |
| Reading and citation-gathering deferred until report-writing time, not treated as a precondition for starting implementation | Matches an established build-to-learn working pattern; the design and feasibility groundwork is complete, and deep literature engagement is most valuable immediately before writing the sections that cite it. |
