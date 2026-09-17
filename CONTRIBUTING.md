# Contributing

## What this project is

A BSc Cybersecurity final-year project at UMaT. As
[README.md](README.md)'s Authorship section states directly: the idea,
research question, architecture, and every functional decision here
belong to one author, as graded academic work. That's not a formality,
it means pull requests that change the actual research contribution
(the trust-checking mechanism, the classifier, the architecture) won't
be merged as external contributions, regardless of quality, since the
work needs to stay attributable to its author for the degree it's
being submitted for.

What's genuinely welcome from anyone:

- **Bug reports.** Something doesn't work the way the docs say it
  should. Open an [issue](https://github.com/DevInBlack001/cti-platform/issues).
- **Security reports.** See [SECURITY.md](SECURITY.md).
- **Documentation corrections.** A broken link, a wrong command, a
  genuinely confusing explanation. Small, factual fixes like this are
  welcome as pull requests.
- **Questions and discussion.** Open an issue. A question that reveals
  a gap in the docs is useful even if the answer turns out to be
  "that's out of scope, see feasibility.md."

If in doubt whether something you want to raise fits one of the above,
open an issue and ask before spending time on a pull request; a
significant change discussed first, before it's written, wastes less
of everyone's time either way.


## Running it locally

The [wiki](https://github.com/DevInBlack001/cti-platform/wiki) covers
installing and configuring the Local Collection Layer and its
connectors. Start with
[Installation](https://github.com/DevInBlack001/cti-platform/wiki/Installation),
then [Configuration](https://github.com/DevInBlack001/cti-platform/wiki/Configuration)
for the environment variables each piece reads, and
[Connectors](https://github.com/DevInBlack001/cti-platform/wiki/Connectors)
for what each source/sink actually does.

Tests:

```bash
collection/.venv/bin/python -m pytest
```

Every test runs against real, grounded behavior: a real FLOD-shaped
SQLite fixture, real GraphQL/API request shapes taken directly from
the actual systems this project connects to. See
[docs/lessons-learned.md](docs/lessons-learned.md) for what building
against those real systems has already caught.


## Conventions this project holds itself to

Worth knowing before submitting a documentation fix, since these apply
to every file here:

- **Plain language.** Minimal jargon; any genuinely necessary
  technical term gets defined in
  [docs/glossary.md](docs/glossary.md) the first time it appears.
- **No hardcoded paths, values, or secrets.** Configuration is
  environment-variable-first with a documented fallback, and a clear,
  plainly stated error when a required value is missing.
- **State things on their own merits.** Docs and comments describe
  what something is and why it's true, standing on its own.
- **Every connector is built and verified against the real system it
  targets.** A connector for a platform nobody involved has real
  access to isn't built yet, on principle; see
  [docs/decision-record.md](docs/decision-record.md).


## License

Apache 2.0, see [LICENSE](LICENSE). Forking and building on this code
under those terms is fine; see [SECURITY.md](SECURITY.md) for what's
in and out of scope for security reports, and note that OpenCTI and
Wazuh are external dependencies this project installs and configures,
never forks, so issues in either of those belong in their own
upstream repositories.
