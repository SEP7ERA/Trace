# 00-OVERVIEW.md

# API Security Scanner

## Project Role

I built this repository as a full-stack API security scanner that turns common API security failure modes into repeatable scan logic. The application accepts a target API, runs selected checks for rate limiting weaknesses, authentication bypass behavior, SQL injection indicators, and IDOR/BOLA-style authorization gaps, then stores the resulting evidence in a structured database-backed report.

I designed the project as a working security engineering artifact rather than a generic sample app. The backend uses FastAPI for request handling, SQLAlchemy for persistence, repository and service layers for separation of concerns, and scanner modules that isolate each vulnerability class. The frontend uses React to expose scan creation and result review without mixing UI state with scanner logic.

The important architectural idea is that the scanner is not a collection of one-off scripts. I treat each scan as a persisted workflow: validate input, authenticate the user, create a scan record, execute selected scanner modules, normalize findings, store evidence, and return a typed response to the frontend.

## Security Context

APIs concentrate business logic, authentication, authorization, and data access behind HTTP interfaces. That makes them a practical target for abuse when controls are inconsistent or missing. I built this project around the kinds of weaknesses that repeatedly appear in API incidents: missing rate limits, broken token validation, SQL injection caused by unsafe query construction, and object-level authorization bugs where changing an identifier exposes another user's data.

The scanner focuses on these areas because they create a useful cross-section of API security engineering. Rate-limit checks exercise request pacing and response-header analysis. Authentication checks force the project to reason about JWT structure, signature validation, and failure behavior. SQL injection checks require payload design, response comparison, and timing baselines. IDOR/BOLA checks require the application to distinguish authentication from authorization.

I also use the project to show how security findings should be represented internally. A scanner should not simply print "vulnerable" or "safe." It should preserve the tested condition, the observed response behavior, the evidence that led to the conclusion, and the remediation guidance that makes the finding actionable.

**Primary engineering scenarios this repository supports:**
- I can run focused API scans before a release and preserve the result history.
- I can validate whether rate limiting is advertised, enforced, or bypassable.
- I can inspect whether JWT handling rejects unsafe algorithm behavior.
- I can evaluate SQL injection signals using error, boolean, and timing-based approaches.
- I can model IDOR/BOLA checks as authorization tests instead of simple endpoint availability tests.

**Security concepts represented in the codebase:**
- OWASP API Security Top 10 2023 concepts mapped into scanner behavior instead of only documentation.
- Rate limiting detection through response codes, headers, request pacing, and bypass-oriented request variation.
- JWT validation analysis, including why unsigned or improperly verified tokens are dangerous.
- SQL injection detection through error signatures, boolean response deltas, and time-based baseline comparison.
- IDOR/BOLA testing as a service-layer authorization problem rather than a routing problem.

**Implementation areas I wanted the repository to demonstrate:**
- Scanner execution with request throttling, retry handling, timeout control, and baseline timing analysis.
- Layered backend organization where routes, services, repositories, models, schemas, and scanners each have a clear responsibility.
- Authentication flow from password hashing to JWT creation to dependency-based user resolution.
- Rate limiting as both a protection mechanism inside the application and a target behavior that the scanner evaluates.
- HTTP request handling that uses session reuse, controlled request spacing, and error recovery instead of uncontrolled request bursts.

**Framework and infrastructure choices:**
- I use FastAPI for typed request/response handling and dependency injection.
- I use SQLAlchemy and Alembic so scan records, users, and findings live in a relational schema with migrations.
- I use Docker multi-stage builds to separate development behavior from production container behavior.
- I use React with TanStack Query so server state, scan results, and refetching behavior remain explicit.
- I use Nginx as the single HTTP entry point that routes API traffic to the backend and static traffic to the frontend.

## Local Runtime Contract

I keep the local startup path in the overview because it defines the expected runtime shape of the repository. The commands below are not the core documentation focus; they are the reproducible environment contract I use to verify that the backend, frontend, database, and reverse proxy are wired together correctly.

```bash
# Clone and navigate (assuming you're already in PROJECTS/intermediate)
cd api-security-scanner

# Copy environment template
cp .env.example .env

# CRITICAL: Edit .env and change SECRET_KEY to something random
# In production this must be a cryptographically secure random string

# Start development environment (includes hot reload)
docker compose -f dev.compose.yml up --build

# Wait for all services to be healthy, then visit:
# - Frontend: http://localhost (or http://localhost:80)
# - Backend API docs: http://localhost:8000/docs
# - Direct API: http://localhost:8000
```

## Repository Structure

The repository is split by responsibility. The backend owns security logic, persistence, authentication, and scanner orchestration. The frontend owns user interaction and result presentation. The Docker and Nginx configuration files define how the services are composed into a working local or production-like environment.

```
api-security-scanner/
├── backend/
│   ├── config.py              # All environment variables and constants
│   ├── core/                  # Infrastructure (database, security, dependencies)
│   ├── models/                # SQLAlchemy models (User, Scan, TestResult)
│   ├── repositories/          # Data access layer, queries isolated here
│   ├── routes/                # FastAPI endpoints (auth, scans)
│   ├── scanners/              # Security testing logic (SQLi, auth, etc)
│   ├── schemas/               # Pydantic validation schemas
│   └── services/              # Business logic layer
├── frontend/
│   └── src/
│       ├── components/        # React UI components
│       ├── hooks/             # TanStack Query hooks for API calls
│       ├── services/          # API client functions
│       └── store/             # Zustand state management
├── conf/
│   ├── docker/                # Dockerfiles for dev and prod
│   └── nginx/                 # Nginx reverse proxy configs
└── compose.yml                # Production Docker Compose
└── dev.compose.yml            # Development with volume mounts
```

The most important boundary in this layout is the backend separation between `routes`, `services`, `repositories`, and `scanners`. I keep route handlers thin so HTTP concerns stay at the edge. I keep service classes responsible for orchestration and authorization checks. I keep repositories responsible for database access. I keep scanners responsible for active security testing and evidence generation.

That separation makes the project easier to reason about during security review. A reviewer can trace a scan from the API route, through the service layer, into the scanner module, and back into persisted `TestResult` records without needing to untangle UI behavior, database queries, and vulnerability logic from the same file.
