```
 █████╗ ██████╗ ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
██╔══██╗██╔══██╗██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
███████║██████╔╝██║    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔══██║██╔═══╝ ██║    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║  ██║██║     ██║    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚═╝     ╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

[![Python](https://img.shields.io/badge/Python-3.13+-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](https://www.docker.com)

> Full-stack API vulnerability scanner targeting the OWASP API Security Top 10 with configurable scan modules and a React dashboard.

## What It Does

- Scans REST APIs against OWASP API Security Top 10 vulnerability categories
- Tests for authentication bypass, injection flaws, IDOR, and rate limiting weaknesses
- SQLi, authentication, IDOR, and rate limit scanner modules with configurable payloads
- JWT auth with bcrypt password hashing and session management
- Scan history tracking with detailed vulnerability reports per endpoint
- Full React dashboard for configuring scans and reviewing results

## Quick Start

```bash
docker compose up -d
```

Visit `http://localhost:8080` to open the dashboard.

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Stack

**Backend:** FastAPI, SQLAlchemy, PostgreSQL, Alembic, httpx, aiohttp

**Frontend:** React, TypeScript, Vite

## Documentation


| Module | Topic |
|--------|-------|
| [00 - Overview](docs/00-OVERVIEW.md) ||
| [01 - Concepts](docs/01-CONCEPTS.md) | theory & real-world breaches |
| [02 - Architecture](docs/02-ARCHITECTURE.md) | System design and data flow |
| [03 - Implementation](docs/03-IMPLEMENTATION.md) | Code walkthrough |

## License

AGPL 3.0
