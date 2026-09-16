# Reading List and Citation Resources

## Deep read, before writing code

1. NIST SP 800-150, *Guide to Cyber Threat Information Sharing*, NIST, 2016.
   https://csrc.nist.gov/pubs/sp/800/150/final
2. C. Wagner, A. Dulaunoy, G. Wagener, A. Iklody, "MISP: The Design and
   Implementation of a Collaborative Threat Intelligence Sharing Platform,"
   WISCS '16, 2016. https://doi.org/10.1145/2994539.2994542
3. STIX 2.1 and TAXII 2.1 specifications, OASIS CTI Technical Committee,
   2021.
   https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html and
   https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
4. J.R. Douceur, "The Sybil Attack," IPTPS 2002. The foundational paper for
   why the validation layer cannot just trust self-reported identity.
5. S.D. Kamvar, M.T. Schlosser, H. Garcia-Molina, "The EigenTrust Algorithm
   for Reputation Management in P2P Networks," WWW 2003, pp. 640-651.
   https://nlp.stanford.edu/pubs/eigentrust.pdf. The classic reference
   model for the reputation-scoring approach.

## Ghana-specific, deep read

6. Cybersecurity Act, 2020 (Act 1038). Establishes the CSA's mandate,
   incident reporting obligations, and critical information infrastructure
   rules.
7. Ghana National Cybersecurity Policy and Strategy.
   https://www.csa.gov.gh/resources.php
8. CSA Annual Report (most recent available). Same resources page.

## Medium read, architecture / evaluation / limitations sections

9. T.D. Wagner, K. Mahbub, E. Palomar, A.E. Abdallah, "Cyber threat
   intelligence sharing: Survey and research directions," Computers &
   Security, vol. 87, 2019, art. 101589.
10. "TrustFed-CTI: A Trust-Aware Federated Learning Framework for
    Privacy-Preserving Cyber Threat Intelligence Sharing Across
    Distributed Organizations," Future Internet, 17(11), 2025, art. 512.
    https://doi.org/10.3390/fi17110512. Closest recent prior art; the
    contribution needs to be positioned against it.
11. M. Bouharoun, B. Taghdouti, M. Erradi, "A Peer to Peer Federated Graph
    Neural Network for Threat Intelligence," NETYS 2023, LNCS vol. 14067,
    Springer.
12. "TrustShare: Secure and Trusted Blockchain Framework for Threat
    Intelligence Sharing," Future Internet, 17(7), 2025, art. 289.
    https://doi.org/10.3390/fi17070289. Read specifically to justify not
    using blockchain.

## Background, skim for context

13. Alwabisi et al., "Cyber Threat Intelligence on Blockchain: A
    Systematic Literature Review," Information (MDPI), 13(3), 2024.
    https://www.mdpi.com/2073-431X/13/3/60. Includes the TITAN framework
    (P2P reputation plus TEE).
14. M. Castro, B. Liskov, "Practical Byzantine Fault Tolerance," OSDI '99,
    1999. Read only if the quorum/voting route needs a formal fault
    threshold justification.

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
