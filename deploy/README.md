# Deployment

Runs this project's OpenCTI instance and everything it needs (storage,
search, message queue, and the standard connectors that ship with any
OpenCTI install). See [docs/architecture.md](../docs/architecture.md)
for why these pieces exist and [docs/glossary.md](../docs/glossary.md)
for any unfamiliar term.

## Before first run

1. Make sure the host or VM this runs on has at least 30GB of free disk
   space, not just free memory. Elasticsearch refuses writes and marks
   itself unhealthy well before the disk actually fills, and this stack
   pulls over 9GB of container images before it writes any data of its
   own. Confirmed working on a 50GB disk / 6GB RAM VM; see
   [docs/lessons-learned.md](../docs/lessons-learned.md) for what it
   looked like to hit this the first time.
2. Copy `.env.example` to `.env`.
3. Fill in every placeholder value in `.env`, generating real secrets as
   the comments in that file describe. Never commit `.env`, it's
   gitignored on purpose.

## Running it

```bash
docker compose up -d
```

First startup takes a few minutes while Elasticsearch and OpenCTI
initialize. Once healthy, OpenCTI is reachable at the address set by
`OPENCTI_HOST`/`OPENCTI_PORT` in your `.env` (`http://localhost:8080` by
default).

## What's deliberately not here

OpenCTI's own official deployment bundles an additional product called
XTM One (a separate AI-assistant platform) by default. This project
doesn't use it: it isn't part of this project's architecture, and it
would add another full web service, background worker, and database to
an already resource-constrained development setup for a feature nothing
here needs.
