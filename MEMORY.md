# Shared memory for AI assistants working on this repo

This project gets worked on by more than one AI coding assistant
(Claude Code, GitHub Copilot, Antigravity, and possibly others later).
Each keeps its own local, gitignored session notes (`CLAUDE.md`,
`agy.md`, `copilot.md`), which don't carry conventions between tools or
between sessions of the same tool. This file is the shared, tracked
source of truth instead: read it before making any change, regardless
of which assistant you are.

Everything below is either a standing convention for how work gets done
in this repo, or a decision that hasn't fully made it into the tracked
docs yet. For the project's own architecture, decisions, roadmap, and
terminology, the docs themselves are authoritative:
[README.md](README.md), [docs/architecture.md](docs/architecture.md),
[docs/decision-record.md](docs/decision-record.md),
[docs/ROADMAP.md](docs/ROADMAP.md),
[docs/feasibility.md](docs/feasibility.md),
[docs/glossary.md](docs/glossary.md), and
[docs/lessons-learned.md](docs/lessons-learned.md). This file doesn't
repeat what's already tracked there; it fills the gap around it.


## Writing and code style, applies everywhere

- **No em dashes, anywhere.** Commit messages, code, comments, docs, or
  any published page. Use a comma, period, or parentheses instead. In
  HTML (an artifact, a rendered page), also check for `&mdash;` and
  `&ndash;` entities, since a plain search for the literal character
  misses them; `&ndash;` is fine for a genuine numeric range like
  "13-14".
- **No comparison framing anywhere**, in code comments, docstrings,
  README/docs prose, or commit messages: no "use X, not Y", "Y instead
  of Z", "Z rather than X" construction that justifies a choice by
  contrasting it against a rejected or hypothetical alternative. State
  the positive fact or reason on its own merits, so it reads correctly
  to someone who never knew the alternative existed. This applies to
  every file with no exceptions, including tables and historical
  records; a comparative table row is still comparison framing.
  - Bad: `# Use Ed25519, not RSA, since it's faster`
  - Better: `# Ed25519: small keys/signatures, fast verify`
- **Detailed code comments**, specific to this project (overrides a
  general "minimal comments" default some assistants default to): every
  source file gets a real module-level comment describing what the file
  does, every function gets a brief comment explaining what it does, and
  non-obvious constants/variables (magic numbers, thresholds) get a
  brief comment too. Comments still follow the two rules above: no em
  dashes, no comparison framing, and they must be factually grounded,
  never a guessed or fabricated claim about behavior that isn't actually
  there.
- **Concrete connectors are named after their tool.** A source or sink
  connector class is named after the specific project/platform it talks
  to (`FlodConnector`, `WazuhConnector`, `OpenCtiSinkConnector`), never
  given a generic name. Only the abstract interface stays generic
  (`SourceConnector`, `SinkConnector` in `collection/*/base.py`).
- **Docs and README use plain language.** Avoid dense technical jargon;
  when a technical term is genuinely necessary (STIX, quorum, Sybil
  attack, Ed25519, GraphQL), use it, and define it in
  [docs/glossary.md](docs/glossary.md) for a reader meeting it for the
  first time.
- **No hardcoded paths, values, or secrets.** Config resolution is
  env-var-first with a candidate-list fallback and a clear "not
  detected" report if nothing matches, never a silent guess. This
  applies to test data too: the phishing scenario's sample data is
  generated fresh by a script at test time, never a static fixture file
  committed to the repo, precisely so nobody cloning the repo can see
  exactly what the "test data" looks like.


## Process rules

- **Run a security check before any push to a remote.** Symlink/TOCTOU
  risk on file reads, injection risk in any constructed command or
  query, unsafe deserialization, unbounded reads, secrets accidentally
  included. A quick check suffices for low-risk diffs (docs, no
  secrets); a fuller pass is warranted for anything touching code,
  credentials, file/network I/O, or deployment config. Two real bugs
  were caught this way already: a SQLite URI injection that bypassed a
  symlink guard, and a sink file with no symlink guard at all, both
  found by a dedicated security pass after the code had already passed
  its own task-level review.
- **Verify every connector against the real system it targets.** FLOD's
  connector was built by reading FLOD's actual
  `stage2/schema.py`; OpenCTI's sink was built by reading OpenCTI's real
  GraphQL schema; Wazuh's connectors were built by reading Wazuh's real
  API spec and a real homelab server's actual config. A connector for a
  platform nobody has real access to shouldn't be built yet, since it
  can't be verified.
- **Attack-test each piece of the information-sharing pipeline as it
  gets built**, on the QEMU test network, as an ongoing rhythm alongside
  development. Report results honestly, including when something breaks
  easily; that's the point.
- **Read freely outside this repo** (other local projects, home
  directory) when it helps understand context, without needing to ask
  each time. Never write, edit, or delete anything outside this repo
  unless it's clearly part of an explicitly requested task.


## Decisions and state not yet fully reflected in the tracked docs

- **Peer sinks auto-register; platform sinks stay manual.** Once the
  Federation and Peer Validation layers exist, a node should
  automatically add a peer as a sink target the moment that peer passes
  validation (its reports get accepted by this node's reputation
  quorum), never a manually maintained peer list. Platform sinks
  (OpenCTI, Wazuh, MISP, whatever else) keep their existing
  operator-configured design; this automatic behavior is specific to
  peer sinks only. See [docs/decision-record.md](docs/decision-record.md)
  for the related sink-scope and multi-sink-fanout decisions already
  written up there.
- **The node dashboard's visual design**: minimalist, both a dark and a
  light theme, color scheme drawn from the Ghana flag (red, gold/yellow,
  green, with the black star as a natural accent), a deliberate choice.
  Main view focuses specifically on peer network status and classifier
  performance; tabs hold deeper per-area analysis; a single, clearly
  identifiable corner link leads out to the node's own CTI platform for
  full browsing. Not built yet, currently scheduled for week 9 (see
  [docs/ROADMAP.md](docs/ROADMAP.md)).
- **A second, QEMU-based test network is planned but not started.**
  Cross-connecting the existing VMware FLOD network (attacker/crowd/
  victim VMs) with a parallel QEMU-based setup, both running FLOD and
  OpenCTI, to prove peer-to-peer sharing works across real separate
  hosts and to check whether FLOD's detection holds up on a topology it
  wasn't originally tuned against. Deferred, with no start date set.
  This host has 14GB RAM and has already hit repeated out-of-memory
  kills during much lighter work, so re-verify available resources
  before starting this and treat the full fleet plus OpenCTI's own
  Docker stack running concurrently as a real open question.
- **`v2` branch status**: sink connectors for OpenCTI and Wazuh, plus a
  Wazuh source connector, are built and passing 85/85 automated tests,
  pushed to `origin/v2`, but not yet merged to `master`. Manual
  verification against the real OpenCTI test VM and the real homelab
  Wazuh server needs to happen first (the Wazuh sink test triggers a
  real active-response firewall block on a live server and needs
  explicit confirmation before running). Don't merge `v2` without that
  verification and an explicit go-ahead.
- **OpenCTI is a plain external dependency, never forked or vendored.**
  A fork was tried and dropped after its license file turned up a
  restrictive Enterprise Edition license covering part of the same
  repository. Don't propose forking or vendoring OpenCTI's source again;
  see [docs/decision-record.md](docs/decision-record.md) for the full
  reasoning.
- **This project targets OpenCTI and Wazuh specifically**, because those
  are the two systems it can actually be verified against (a real
  OpenCTI test VM and a real homelab Wazuh server). A closed or
  proprietary platform comes into scope once there's real access to
  verify a connector against it.
