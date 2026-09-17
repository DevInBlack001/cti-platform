# Reading List and Citation Resources

A list of sources to cite in the final report, grouped by how closely
each needs to be read. Terms in *italics* are defined in the
[glossary](glossary.md) the first time they appear; this page is mostly a
citation list, so most other terms are left as the papers themselves use
them.

## Deep read, before writing code

1. NIST SP 800-150, *Guide to Cyber Threat Information Sharing*, NIST, 2016.
   https://csrc.nist.gov/pubs/sp/800/150/final
2. C. Wagner, A. Dulaunoy, G. Wagener, A. Iklody, "MISP: The Design and
   Implementation of a Collaborative Threat Intelligence Sharing Platform,"
   WISCS '16, 2016. https://doi.org/10.1145/2994539.2994542
3. *[STIX](glossary.md#stix)* 2.1 and *[TAXII](glossary.md#taxii)*
   specifications, OASIS CTI Technical Committee, 2021.
   https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html and
   https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
4. J.R. Douceur, "The Sybil Attack," IPTPS 2002. The paper that first
   described the *[Sybil attack](glossary.md#sybil-attack)* problem this
   project's Peer Validation Layer has to guard against.
5. S.D. Kamvar, M.T. Schlosser, H. Garcia-Molina, "The EigenTrust Algorithm
   for Reputation Management in P2P Networks," WWW 2003, pp. 640-651.
   https://nlp.stanford.edu/pubs/eigentrust.pdf. A widely cited approach
   to *[EigenTrust](glossary.md#eigentrust)*-style reputation scoring,
   read as a reference point before designing this project's own version.
6. D.J. Bernstein, N. Duif, T. Lange, P. Schwabe, B.-Y. Yang, "High-speed
   high-security signatures," Journal of Cryptographic Engineering, vol.
   2, 2012, pp. 77-89. https://ed25519.cr.yp.to/ed25519-20110926.pdf. The
   original paper for *[Ed25519](glossary.md#ed25519)*, the signature
   scheme every Threat Observation this project produces is actually
   signed with.
7. P. Maymounkov, D. Mazières, "Kademlia: A Peer-to-peer Information
   System Based on the XOR Metric," IPTPS 2002, LNCS vol. 2429, Springer,
   pp. 53-65. The peer-discovery design an earlier piece of prior work
   applied directly to this project's Federation Layer is built on; see
   [decision-record.md](decision-record.md).
8. S. Rose, O. Borchert, S. Mitchell, S. Connelly, "Zero Trust
   Architecture," NIST Special Publication 800-207, August 2020.
   https://csrc.nist.gov/pubs/sp/800/207/final. Grounds the continuous
   verification this project's own Peer Validation Layer applies to
   every peer, all the time, starting from the moment a peer joins and
   kept up after; see [decision-record.md](decision-record.md).
9. J.H. Friedman, "Greedy Function Approximation: A Gradient Boosting
   Machine," Annals of Statistics, vol. 29, no. 5, 2001, pp. 1189-1232.
   The foundational paper for
   *[gradient-boosted-trees](glossary.md#gradient-boosted-trees)*, the
   model type behind this project's own classifier, read as a reference
   point the same way EigenTrust is for the trust mechanism.

## Ghana-specific, deep read

10. Cybersecurity Act, 2020 (*[Act 1038](glossary.md#act-1038)*). Sets out
    the *[CSA](glossary.md#csa)*'s authority, incident-reporting rules,
    and rules for critical infrastructure.
11. Ghana National Cybersecurity Policy and Strategy.
    https://www.csa.gov.gh/resources.php
12. CSA Annual Report (most recent available). Same resources page.

## Medium read, for the architecture / evaluation / limitations sections

13. T.D. Wagner, K. Mahbub, E. Palomar, A.E. Abdallah, "Cyber threat
    intelligence sharing: Survey and research directions," Computers &
    Security, vol. 87, 2019, art. 101589.
14. "TrustFed-CTI: A Trust-Aware Federated Learning Framework for
    Privacy-Preserving Cyber Threat Intelligence Sharing Across
    Distributed Organizations," Future Internet, 17(11), 2025, art. 512.
    https://doi.org/10.3390/fi17110512. The closest recent prior work;
    this project's own contribution needs to be clearly compared against
    it.
15. M. Bouharoun, B. Taghdouti, M. Erradi, "A Peer to Peer Federated Graph
    Neural Network for Threat Intelligence," NETYS 2023, LNCS vol. 14067,
    Springer.
16. "TrustShare: Secure and Trusted Blockchain Framework for Threat
    Intelligence Sharing," Future Internet, 17(7), 2025, art. 289.
    https://doi.org/10.3390/fi17070289. Read specifically to explain why
    this project does not use a blockchain.

## Background, skim for context

17. Alwabisi et al., "Cyber Threat Intelligence on Blockchain: A
    Systematic Literature Review," Information (MDPI), 13(3), 2024.
    https://www.mdpi.com/2073-431X/13/3/60. Gives a map of the wider
    trust/reputation/blockchain research space in one place.
18. M. Castro, B. Liskov, "Practical Byzantine Fault Tolerance," OSDI '99,
    1999. Only needed if the quorum mechanism ends up needing a formal
    proof of how many dishonest nodes it can tolerate, see
    *[Byzantine Fault Tolerance](glossary.md#byzantine-fault-tolerance-bft)*.

## Ghana cybersecurity landscape, for the motivation section

- CERT-GH incident statistics, January to July 2026: 3,876 incidents,
  1,818 (about 47%) linked to online fraud (CSA Director-General Divine
  Selase Agbeti, National Cyber Security Awareness Month launch,
  September 2026).
- Credential leak affecting 35 organizations (ministries, banks,
  hospitals, universities), disclosed September 2025.
- Ghana's 13 designated Critical Information Infrastructure sectors under
  Act 1038 sections 35 to 40, Gazette Notice 132 (2021), each with a
  sector-CERT coordinated by CERT-GH.

News-sourced statistics should be cited as secondary reporting of
CSA/CERT-GH figures. Cross-check primary numbers against CSA's own
published reports directly before finalizing the report, since the
department will expect primary-source citation where available.
