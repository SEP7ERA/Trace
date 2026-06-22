# 01-CONCEPTS.md

# Core Security Concepts

This file serves as the conceptual deep dive behind the API Security Scanner. Instead of treating rate limiting, authentication, SQL injection, and IDOR/BOLA as isolated vocabulary terms, it explains how each concept influences the scanner logic, the result model, and the defensive assumptions inside the repository.

The scanner is built around a simple design idea: every security concept should map to something observable in HTTP traffic, application behavior, timing, response structure, or authorization boundaries. Each issue is described in terms of the detection method, the evidence stored, and the engineering trade-offs that shape the implementation.

## Rate Limiting

### What It Is

Rate limiting is modeled as a control plane decision: the API has to decide how many requests a client can make, how the client is identified, and what response is returned when the threshold is exceeded. In this project, the important question is less about defining rate limiting and more about verifying it from the outside.

The scanner evaluates whether an API exposes rate-limit headers, whether those headers appear to be enforced, and whether repeated requests eventually produce a blocking response such as HTTP `429 Too Many Requests`. The important distinction in my implementation is that advertised limits and enforced limits are not the same thing.

### Why It Matters

Rate limiting matters in this project because it directly affects how safely and reliably an API handles abuse patterns. Missing or weak limits can enable credential stuffing, brute-force attempts, scraping, resource exhaustion, and cost amplification. From a scanner perspective, that means the implementation needs to look for both the presence of controls and signs that those controls actually change server behavior.

The design also accounts for the fact that rate limiting is not only a denial-of-service defense. In API security, it supports authentication hardening, object enumeration resistance, and cloud cost protection. A scanner that only checks for a single header would miss most of that operational reality.

Rate limiting affects several real-world abuse categories:

- **Credential stuffing** - repeated login attempts using known credential pairs
- **Data scraping** - repeated collection of public or semi-public API resources
- **Brute force attacks** - repeated guessing against passwords, API keys, IDs, or tokens
- **Cost attacks** - repeated triggering of expensive application or cloud operations

### Scanner Modeling Approach

The rate-limit scanner is built around response-pattern analysis. It sends a bounded number of requests, captures response status codes and headers, and classifies the target into a small set of states. The method is intentionally conservative: the scanner does not need to overwhelm the target to learn whether the API signals or enforces limits.

The core detection path lives in `backend/scanners/rate_limit_scanner.py`:

```python
# Lines 62-145
def _detect_rate_limiting(self, test_request_count: int = 20) -> dict[str, Any]:
    """
    Detect rate limiting by analyzing headers and response patterns
    """
    rate_limit_patterns = RateLimitBypassPayloads.get_header_patterns()
    
    results = {
        "rate_limit_detected": False,
        "rate_limit_headers": {},
        "enforcement_status": None,
    }
    
    for attempt in range(1, test_request_count + 1):
        response = self.make_request("GET", "/")
        
        # Check for standard rate limit headers
        for header_type, pattern in rate_limit_patterns.items():
            for header_name, header_value in headers_lower.items():
                if re.search(pattern, header_name, re.IGNORECASE):
                    results["rate_limit_headers"][header_type] = {
                        "header_name": header_name,
                        "value": header_value,
                    }
                    results["rate_limit_detected"] = True
        
        # Check if we hit the limit
        if response.status_code == 429:
            results["enforcement_status"] = "ACTIVE"
            results["attempts_until_limit"] = attempt
            break
```

In this implementation, the scanner collects two types of evidence. First, it inspects headers such as `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset`. Second, it watches for enforcement behavior, especially a `429` response. This separation lets the report distinguish between an API that merely advertises limits and an API that actively blocks excess requests.

The target is classified into three scanner states:

1. **No rate limiting** - repeated requests produce no limit headers and no blocking response.
2. **Headers only** - the API exposes limit metadata but does not block during the test window.
3. **Active enforcement** - the API eventually returns `429` or another clear throttling signal.

### Attack Surface Considerations

Rate-limit bypass concepts are included because a scanner has to understand how weak identifiers affect enforcement. The issue is not only whether a limit exists, but whether the API uses an identifier that can be spoofed or rotated.

1. **IP header spoofing** - Some rate limiters trust headers such as `X-Forwarded-For`. My scanner treats that as risky because a client can rotate spoofed values unless the upstream proxy chain is trusted and normalized.

2. **Distributed request sources** - Per-IP limits can fail when traffic is distributed across many clients. The project does not simulate distributed abuse, but the documentation records the limitation.

3. **Endpoint variation bypass** - Some systems apply limits inconsistently across path variants such as `/api/users`, `/API/users`, `/api/users/`, or `/api/users?`. Route normalization is treated as part of rate-limit quality.

4. **Resource exhaustion despite limits** - A limit can exist but still be too permissive for expensive endpoints. The scanner can flag missing enforcement, but it cannot fully prove that a chosen threshold is appropriate for the application’s cost profile.

### Defensive Model

The scanner is designed around the assumption that rate limiting should exist at multiple layers. The repository documents those layers because they explain why a single application-level finding is only part of the defensive picture.

**Layer 1: Edge/CDN level**  
Systems such as Cloudflare, AWS WAF, or similar edge controls are expected to absorb obvious abuse before traffic reaches the application.

**Layer 2: API gateway**  
An API gateway or reverse proxy is expected to enforce coarse-grained controls by IP, API key, route, or user identity.

**Layer 3: Application level**  
Inside this project, application-level limits are implemented with SlowAPI in the FastAPI app factory:

```python
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
```

The routes apply specific limits where abuse risk is higher, such as registration and scan creation:

```python
@router.post("/register", ...)
@limiter.limit(settings.API_RATE_LIMIT_REGISTER)  # "15/minute" from config
async def register(request: Request, ...):
    return AuthService.register_user(db, user_data)
```

The scanner’s findings are meant to support these defensive decisions. A useful report should tell me whether the API exposes limit metadata, whether limits are enforced, and whether obvious bypass patterns appear to work.

**Critical defensive expectations:**

- Client-controlled forwarding headers are not trusted unless a trusted proxy normalizes them.
- Combined identifiers such as IP, user ID, API key, route, and session context are preferred.
- Repeated violations should trigger increasing friction or lockout behavior.
- `Retry-After` or equivalent metadata should be returned when clients are blocked.
- Limit violations should be logged for security monitoring and abuse analysis.

## Broken Authentication

### What It Is

In this repository, authentication is the boundary that decides whether a request is connected to a known identity. Broken authentication means that boundary can be bypassed, forged, weakened, or misapplied. Because the project is API-focused, authentication is modeled primarily through bearer tokens and JWT validation behavior.

The scanner focuses on JWTs because they are common in API systems and fail in predictable ways when libraries are misconfigured. A JWT is treated as a signed assertion that must be verified before the payload is trusted.

Common API authentication mechanisms include:

- **Session tokens** - server-side state keyed by a session identifier
- **JWT tokens** - signed claims sent by the client and verified by the server
- **API keys** - long-lived application identifiers or secrets
- **OAuth 2.0 access tokens** - delegated authorization tokens issued by an identity provider

### Why It Matters

Authentication failures are high impact because the rest of the API often assumes identity has already been established. If a token can be forged, accepted without a signature, or mapped to a user without proper validation, then downstream authorization checks become unreliable.

For this project, authentication is also important because the scanner itself supports authenticated scanning. The implementation therefore has to account for how tokens are structured, how they are validated, and how misconfigurations appear from the outside.

### JWT Modeling Approach

A JWT has three period-separated sections:

```
header.payload.signature
```

Example token shape:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIn0.signature_here
```

The decoded header records the algorithm and token type:

```json
{"alg": "HS256", "typ": "JWT"}
```

The decoded payload carries claims such as the subject:

```json
{"sub": "user@example.com"}
```

The signature is what makes the payload trustworthy. Conceptually, the server verifies a construction like this:

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret
)
```

The important implementation rule is that the payload is not trusted until the signature, algorithm, and expiration are verified. That expectation is enforced in the project’s token validation code:

```python
def decode_token(token: str) -> dict[str, str]:
    """
    Decode and verify a JWT token
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]  # Explicitly specify allowed algorithms
        )
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {str(e)}") from e
```

This implementation detail matters because `algorithms=[settings.ALGORITHM]` is an allowlist. The server does not accept whatever algorithm the token header asks for; it verifies against the configured algorithm only.

### Attack Surface Considerations

1. **None algorithm attack** - Some JWT implementations historically accepted `alg: none`, which means no signature. My scanner checks this because accepting unsigned tokens collapses the authentication boundary.

```python
def _test_none_algorithm(self) -> dict[str, Any]:
    """
    Test if server accepts JWT with 'none' algorithm
    """
    header, payload, signature = self.auth_token.split(".")
    
    none_variants = ["none", "None", "NONE", "nOnE"]  # Case variations
    
    for variant in none_variants:
        malicious_header = self._base64url_encode(
            json.dumps({"alg": variant, "typ": "JWT"})
        )
        malicious_token = f"{malicious_header}.{payload}."  # No signature
        
        response = self.make_request(
            "GET", "/",
            headers={"Authorization": f"Bearer {malicious_token}"}
        )
        
        if response.status_code == 200:
            return {"vulnerable": True, "algorithm_variant": variant}
```

2. **Missing authentication** - Some endpoints that should be protected are reachable without a token. My auth scanner creates a separate session without credentials so it can compare protected and unprotected behavior.

```python
def _test_missing_authentication(self) -> dict[str, Any]:
    """
    Test if endpoint requires authentication
    """
    session_without_auth = self.session.__class__()  # New session, no token
    
    response = session_without_auth.get(self.target_url, timeout=...)
    
    if response.status_code == 200:
        return {"vulnerable": True, "description": "Endpoint accessible without authentication"}
```

3. **Weak secret keys** - If an HMAC JWT secret is guessable, an attacker can forge tokens. The scanner can reason about weak-token behavior, but secret strength ultimately depends on server-side configuration.

4. **Algorithm confusion** - Some systems expect asymmetric signing but accidentally accept symmetric algorithms. That can allow an attacker to misuse a public key as an HMAC secret. The project documents this as a class of JWT configuration failure.

### Defensive Model

The project implements JWT creation and validation as a controlled path. Token creation adds an expiration claim and signs with the configured secret:

```python
def create_access_token(data: dict[str, str], expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=1440))
    to_encode.update({"exp": expire})
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,  # Must be cryptographically random, 256+ bits
        algorithm=settings.ALGORITHM  # "HS256"
    )
    return encoded_jwt
```

Token validation happens through a dependency that extracts the bearer token, verifies the token, reads the subject claim, and loads the user from the database:

```python
async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> UserResponse:
    try:
        payload = decode_token(credentials.credentials)
        email: str | None = payload.get("sub")
        
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        user = UserRepository.get_by_email(db, email)
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return UserResponse.model_validate(user)
```

The implementation intentionally loads the user from the database after token verification instead of trusting the token payload alone. That gives the application a chance to reject tokens for users that no longer exist or should no longer be active.

**Critical defensive expectations:**

- HMAC-signed JWTs require a high-entropy secret.
- Accepted algorithms are explicitly allowlisted.
- Signatures are verified before claims are read as trusted data.
- Expiration claims are included and validated.
- Sensitive routes require authentication.
- A production-grade version would use shorter-lived access tokens and refresh-token rotation.

### Implementation Pitfalls Captured by the Scanner

**Mistake 1: Trusting unverified tokens**

```python
# Bad - decodes without verifying signature
import base64, json
header, payload, sig = token.split(".")
data = json.loads(base64.b64decode(payload))
user_id = data["user_id"]  # Attacker controlled!

# Good - verifies signature first
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
user_id = payload["user_id"]  # Safe to use
```

**Mistake 2: Ignoring expiration**

```python
# Bad - no expiration check
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], options={"verify_exp": False})

# Good - validates expiration
payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])  # verify_exp=True by default
```

These examples remain in the repo because they document the exact failure modes the authentication scanner is designed to detect or reason about.

## SQL Injection

### What It Is

SQL injection is modeled as a failure to keep code and data separated. The vulnerable pattern is not merely “bad input”; it is the application building executable SQL by combining query text with untrusted values.

A minimal vulnerable query looks like this:

```python
query = f"SELECT * FROM users WHERE email = '{email}'"
```

If attacker-controlled input changes the query structure, the database receives a different instruction than the developer intended:

```sql
SELECT * FROM users WHERE email = 'admin'--'
```

The comment operator changes the meaning of the query. That is the core behavior my SQL injection scanner tries to identify through errors, response differences, and timing differences.

### Why It Matters

SQL injection remains important because APIs often expose database-backed search, lookup, authentication, reporting, or filtering endpoints. Even when an ORM is present, raw query helpers, dynamic filters, and unsafe string construction can reintroduce the vulnerability.

In this repository, SQL injection detection is useful because it demonstrates how a scanner can infer server-side query behavior without seeing the source code of the target API. The implementation has to collect weak signals and reduce false positives.

Common conditions that lead to SQL injection include:

- Concatenating user input into query strings
- Misusing ORM raw SQL features
- Building dynamic SQL from user-controlled fields
- Trusting values received from internal services without validation

### Scanner Modeling Approach

The SQL injection scanner uses three detection methods. Each method exists because not every vulnerable system leaks the same kind of evidence.

**1. Error-based SQLi** - The scanner sends payloads intended to break unsafe SQL construction and then looks for database-specific error messages.

```python
def _test_error_based_sqli(self) -> dict[str, Any]:
    """
    Test for error based SQL injection
    """
    error_signatures = SQLiPayloads.get_error_signatures()  # MySQL, Postgres, MSSQL, Oracle
    basic_payloads = SQLiPayloads.BASIC_AUTHENTICATION_BYPASS
    
    for payload in basic_payloads:
        response = self.make_request("GET", f"/?id={payload}")
        response_text_lower = response.text.lower()
        
        # Look for database error signatures
        for db_type, signatures in error_signatures.items():
            for signature in signatures:
                if signature in response_text_lower:
                    return {
                        "vulnerable": True,
                        "database_type": db_type,
                        "payload": payload,
                        "error_signature": signature
                    }
```

The database error signatures are centralized in `scanners/payloads.py` so the scanner logic stays separate from payload storage:

```python
ERROR_SIGNATURES = {
    "mysql": ["sql syntax", "mysql_fetch", "mysql error"],
    "postgres": ["postgresql", "pg_query", "syntax error"],
    "mssql": ["sqlserver jdbc driver", "sqlexception"],
    "oracle": ["ora-", "oracle.jdbc", "pl/sql"],
}
```

**2. Boolean-based blind SQLi** - When database errors are hidden, the scanner compares responses from conditions that should evaluate differently only if the input is being interpreted as SQL.

```python
def _test_boolean_based_sqli(self) -> dict[str, Any]:
    """
    Test for boolean based blind SQL injection
    """
    baseline_response = self.make_request("GET", "/?id=1")
    baseline_length = len(baseline_response.text)
    
    # Try true conditions: ' AND 1=1--
    true_payloads = [p for p in boolean_payloads if "AND '1'='1" in p or "AND 1=1" in p]
    true_lengths = []
    for payload in true_payloads:
        response = self.make_request("GET", f"/?id={payload}")
        true_lengths.append(len(response.text))
    
    # Try false conditions: ' AND 1=2--
    false_payloads = [p for p in boolean_payloads if "AND '1'='2" in p]
    false_lengths = []
    for payload in false_payloads:
        response = self.make_request("GET", f"/?id={payload}")
        false_lengths.append(len(response.text))
    
    avg_true = statistics.mean(true_lengths)
    avg_false = statistics.mean(false_lengths)
    length_diff = abs(avg_true - avg_false)
    
    if length_diff > 100:  # Significant difference
        return {"vulnerable": True, "length_difference": length_diff}
```

This method does not rely on a single response. Average response lengths for true-condition and false-condition payloads keep one noisy response from deciding the result.

**3. Time-based blind SQLi** - When responses look the same, the scanner uses database delay functions and compares the observed response time to a measured baseline.

```python
def _test_time_based_sqli(self, delay_seconds: int = 5) -> dict[str, Any]:
    """
    Test for time based blind SQL injection
    Uses baseline timing comparison with statistical analysis
    """
    # Establish normal response time
    baseline_mean, baseline_stdev = self.get_baseline_timing("/")
    expected_delay_time = baseline_mean + delay_seconds
    
    delay_payloads = {
        "mysql": [p for p in all_time_payloads if "SLEEP" in p],
        "postgres": [p for p in all_time_payloads if "pg_sleep" in p],
        "mssql": [p for p in all_time_payloads if "WAITFOR" in p],
    }
    
    for db_type, payloads in delay_payloads.items():
        for payload in payloads:
            delay_times = []
            for _ in range(3):  # Multiple samples
                response = self.make_request("GET", f"/?id={payload}", timeout=delay_seconds + 10)
                elapsed = getattr(response, "request_time", 0.0)
                delay_times.append(elapsed)
            
            avg_delay = statistics.mean(delay_times)
            
            if avg_delay >= expected_delay_time - 1:  # Within 1 second of expected
                return {"vulnerable": True, "database_type": db_type, "response_time": f"{avg_delay:.3f}s"}
```

Time-based detection is the most sensitive to network variance, so it is treated as a statistical signal rather than a simple stopwatch check. The scanner establishes baseline timing first, groups delay payloads by database family, and samples each candidate multiple times.

### Payload Families

The payloads in `scanners/payloads.py` are grouped by technique so the scanner can report not only that a target looks vulnerable, but which method produced evidence.

**1. Authentication bypass payloads**

```python
BASIC_AUTHENTICATION_BYPASS = [
    "' OR '1'='1",        # Makes WHERE clause always true
    "' OR 1=1--",         # Comments out rest of query
    "admin'--",           # Logs in as admin by ending query early
    ") or '1'='1--",      # Escapes parentheses in complex queries
]
```

**2. Union-based extraction payloads**

```python
UNION_BASED = [
    "' UNION SELECT NULL--",                    # Find column count
    "' UNION SELECT username,password FROM users--",  # Extract data
    "' UNION SELECT NULL,version()--",          # Get database version
]
```

**3. Stacked query payloads**

```python
STACKED_QUERIES = [
    "'; DROP TABLE users--",                    # Delete data
    "'; INSERT INTO users VALUES('hacker','password')--",  # Add accounts
    "'; EXEC xp_cmdshell('whoami')--",         # Run OS commands (MSSQL)
]
```

These payload families are documented because they explain the scanner’s coverage boundaries. The project does not attempt to be a full SQL injection exploitation framework; it focuses on detection evidence and remediation guidance.

### Defensive Model

My defensive assumption is simple: user-controlled values must be passed as parameters, not inserted into query strings.

**Vulnerable construction:**

```python
# BAD - string concatenation
email = request.get("email")
query = f"SELECT * FROM users WHERE email = '{email}'"
result = db.execute(query)
```

**Safe SQLAlchemy construction:**

```python
# GOOD - parameterized query
email = request.get("email")
result = db.query(User).filter(User.email == email).first()

# SQLAlchemy generates safe SQL:
# SELECT * FROM users WHERE email = :email_1
# Parameters: {'email_1': 'user@example.com'}
```

The project uses the repository pattern to keep database access predictable and auditable. For example, user lookup is handled through the repository layer:

```python
@staticmethod
def get_by_email(db: Session, email: str) -> User | None:
    """
    Get user by email address
    """
    return db.query(User).filter(User.email == email).first()
```

SQLAlchemy turns `.filter(User.email == email)` into a parameterized query. That separation is the actual defense: the value remains data, not executable SQL.

**Critical defensive expectations:**

- ORM query builders are preferred for routine data access.
- Parameterized queries are used when raw SQL is necessary.
- Input types are validated before they reach query construction.
- Least-privilege database accounts are used.
- Database error details are not leaked in production responses.

### Implementation Pitfalls Captured by the Scanner

**Mistake 1: Using raw SQL unsafely**

```python
# Bad - raw SQL with concatenation
email = request.get("email")
query = f"SELECT * FROM users WHERE email = '{email}'"
result = db.session.execute(text(query))  # Still vulnerable!

# Good - raw SQL with parameters
result = db.session.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email}
)
```

**Mistake 2: Trusting internal data without validation**

```python
# Bad - assumes data from another service is safe
external_api_result = fetch_from_partner()
user_id = external_api_result["user_id"]
query = f"SELECT * FROM orders WHERE user_id = {user_id}"  # Can still be exploited
```

These patterns are included because they are the same coding shortcuts that cause real scanners to find SQL injection in otherwise modern applications.

## IDOR/BOLA (Broken Object Level Authorization)

### What It Is

IDOR/BOLA is modeled as an authorization failure at the object boundary. Authentication proves who is making the request; object-level authorization proves that identity is allowed to access the specific resource being requested.

A common vulnerable route shape looks like this:

```
GET /api/users/123/orders
```

The issue is not the presence of an object ID by itself. The issue is that the API may check for a valid token but fail to verify that the authenticated user owns or is allowed to access object `123`.

### Why It Matters

IDOR/BOLA is especially important for APIs because object IDs often appear directly in URLs, request bodies, and JSON responses. If the application uses predictable identifiers and weak authorization checks, an attacker can enumerate resources by changing those identifiers.

For this project, IDOR/BOLA is also a good example of why scanner evidence has to be interpreted carefully. A `200 OK` response for another object ID is suspicious, but the scanner has to record enough context to help a human confirm whether the access was actually unauthorized.

### Scanner Modeling Approach

The IDOR scanner focuses on two patterns: extracting candidate IDs from responses and then testing whether related IDs are accessible.

**1. ID extraction** - The scanner searches API responses for UUIDs and numeric identifiers that can become candidate object references.

```python
def _extract_ids_from_response(self) -> list[Any]:
    """
    Extract potential IDs from API response
    """
    response = self.make_request("GET", "/")
    
    # Look for UUIDs: a1b2c3d4-1234-5678-9abc-def012345678
    uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    uuids = re.findall(uuid_pattern, response.text, re.IGNORECASE)
    
    # Look for numeric IDs: "id": 123
    numeric_id_pattern = r'"id"\s*:\s*(\d+)'
    numeric_ids = re.findall(numeric_id_pattern, response.text)
    
    ids = []
    ids.extend(uuids[:3])
    ids.extend([int(nid) for nid in numeric_ids[:3]])
    
    return ids
```

After extraction, the scanner tests controlled ID variations and records whether the target returns successful responses where an authorization failure or not-found response would be expected.

```python
def _test_numeric_id_manipulation(self, extracted_ids: list[Any]) -> dict[str, Any]:
    """
    Test numeric ID manipulation for IDOR
    """
    numeric_ids = [id_val for id_val in extracted_ids if isinstance(id_val, int)]
    
    base_id = numeric_ids[0]
    test_ids = [0, -1, 1, 2, 9999, 99999, 999999]  # Common patterns
    
    accessible_unauthorized = []
    
    for test_id in test_ids:
        if test_id == base_id:
            continue
        
        response = self.make_request("GET", f"/{test_id}")
        
        if response.status_code == 200:  # Should be 403 or 404
            accessible_unauthorized.append({
                "id": test_id,
                "status_code": response.status_code,
                "response_length": len(response.text)
            })
    
    if accessible_unauthorized:
        return {"vulnerable": True, "unauthorized_access": accessible_unauthorized}
```

**2. Predictable identifier patterns** - The scanner checks whether numeric IDs appear sequential, because predictable IDs make enumeration easier and increase the impact of missing authorization.

```python
def _test_predictable_id_patterns(self) -> dict[str, Any]:
    """
    Test if IDs follow predictable patterns
    """
    ids1 = self._extract_ids_from_response()
    ids2 = self._extract_ids_from_response()
    
    numeric_ids1 = [id for id in ids1 if isinstance(id, int)]
    numeric_ids2 = [id for id in ids2 if isinstance(id, int)]
    
    if len(numeric_ids1) >= 2:
        diff1 = abs(numeric_ids1[1] - numeric_ids1[0])
        
        if len(numeric_ids2) >= 2:
            diff2 = abs(numeric_ids2[1] - numeric_ids2[0])
            
            if diff1 == diff2 and diff1 == 1:  # Increments by 1 each time
                return {
                    "vulnerable": True,
                    "pattern_type": "Sequential IDs",
                    "id_difference": diff1
                }
```

This detection does not claim that sequential IDs are automatically a vulnerability. Instead, predictability is treated as an amplifier: it becomes dangerous when paired with missing object-level authorization.

### Payload Families

The IDOR payloads are intentionally simple because the vulnerability is usually about authorization logic, not complicated input syntax.

**1. Numeric ID manipulation**

```python
NUMERIC_ID_MANIPULATIONS = [
    0,        # First record
    -1,       # May wrap to last record  
    1,        # Common starting ID
    9999,     # Try common ranges
    999999,   # Higher ranges
]
```

**2. String ID manipulation**

```python
STRING_ID_MANIPULATIONS = [
    "admin",               # Privileged accounts
    "root",
    "test",
    "../../../etc/passwd", # Path traversal attempts
]
```

**3. UUID edge cases** - UUIDs are harder to guess, but they do not replace authorization. The scanner still accounts for weak UUID validation, all-zero UUIDs, and systems that assume random-looking IDs are authorization controls.

### Defensive Model

My defensive model is that every object lookup should be scoped by the current user or authorization context. The object ID alone should never be enough to retrieve sensitive data.

**Vulnerable lookup:**

```python
@router.get("/api/documents/{doc_id}")
async def get_document(doc_id: int, user: User = Depends(get_current_user)):
    document = db.query(Document).filter(Document.id == doc_id).first()
    return document  # IDOR vulnerability - didn't check ownership
```

**Scoped lookup:**

```python
@router.get("/api/documents/{doc_id}")
async def get_document(doc_id: int, user: User = Depends(get_current_user)):
    document = db.query(Document).filter(
        Document.id == doc_id,
        Document.owner_id == user.id  # Authorization check
    ).first()
    
    if not document:
        raise HTTPException(status_code=404, detail="Document not found")
    
    return document
```

The project applies the same principle in `services/scan_service.py`, where a scan lookup is followed by an ownership check before the response is returned:

```python
@staticmethod
def get_scan_by_id(db: Session, scan_id: int, user_id: int) -> ScanResponse:
    """
    Get scan by ID with authorization check
    """
    scan = ScanRepository.get_by_id(db, scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # CRITICAL: Check if user owns this scan
    if scan.user_id != user_id:
        raise HTTPException(status_code=403, detail="Not authorized to access this scan")
    
    return ScanResponse.model_validate(scan)
```

This authorization check stays in the service layer so the rule is tied to the business operation, not just one route handler. That reduces the chance that another route accidentally exposes the same resource without checking ownership.

**Critical defensive expectations:**

- Object ownership is checked on every read and write path.
- UUIDs are treated as an identifier strategy, not an authorization strategy.
- Scoped queries such as `WHERE id = ? AND owner_id = ?` are preferred.
- Resource existence is not leaked when a user is not authorized.
- Suspicious patterns such as rapid object-ID probing are logged.

### Implementation Pitfalls Captured by the Scanner

**Mistake 1: Checking authorization only on write operations**

```python
# Bad - checks auth for POST but not GET
@router.post("/api/orders/{order_id}/cancel")
async def cancel_order(order_id: int, user: User = Depends()):
    order = db.get(Order, order_id)
    if order.user_id != user.id:  # Auth check here
        raise HTTPException(403)
    order.status = "cancelled"

@router.get("/api/orders/{order_id}")
async def get_order(order_id: int):
    return db.get(Order, order_id)  # No auth check - vulnerable
```

**Mistake 2: Treating UUIDs as access control**

```python
# Bad - assumes UUID means authorization not needed
@router.get("/api/documents/{doc_uuid}")
async def get_document(doc_uuid: str):
    return db.query(Document).filter(Document.uuid == doc_uuid).first()
    # Still vulnerable! UUIDs are hard to guess but not impossible

# Good - check authorization even with UUIDs
@router.get("/api/documents/{doc_uuid}")
async def get_document(doc_uuid: str, user: User = Depends()):
    doc = db.query(Document).filter(
        Document.uuid == doc_uuid,
        Document.owner_id == user.id
    ).first()
    if not doc:
        raise HTTPException(404)
    return doc
```

## How These Concepts Relate

The scanner is designed around the fact that API weaknesses compound. A single issue is often manageable, but combined weaknesses can turn into a complete breach path.

```
No Rate Limiting
    ↓
  enables
    ↓
Rapid IDOR Enumeration
    ↓
 combined with
    ↓
Broken Authentication
    ↓
  allows
    ↓
SQL Injection Exploitation
    ↓
   results in
    ↓
Complete Data Breach
```

A weak rate limiter makes IDOR enumeration faster. Broken authentication makes unauthorized identity claims possible. SQL injection can turn one exposed endpoint into database-level compromise. The scanner sections are separate in code, but the risk model is connected.

A realistic chain could look like this:

1. Missing rate limits allow rapid object probing.
2. Weak authentication accepts malformed or forged tokens.
3. Broken object authorization exposes another user’s resource.
4. SQL injection on an authenticated endpoint exposes broader database contents.

The defensive conclusion is that layered controls are required. Fixing only one category may reduce risk, but it does not eliminate the combined attack path.

## Industry Standards and Frameworks

### OWASP Top 10

This repository maps directly to several OWASP API Security Top 10 categories:

- **API1:2023 Broken Object Level Authorization** - represented by the IDOR/BOLA scanner
- **API2:2023 Broken Authentication** - represented by the authentication scanner
- **API4:2023 Unrestricted Resource Consumption** - represented by the rate-limit scanner
- **API8:2023 Security Misconfiguration** - represented across multiple scanner checks

OWASP is used as a control-language anchor so findings are easier to explain in a professional security context.

### MITRE ATT&CK

The scanner concepts also connect to ATT&CK-style behavior:

- **T1190** - Exploit Public-Facing Application
- **T1110** - Brute Force
- **T1212** - Exploitation for Credential Access
- **T1078** - Valid Accounts

This project is not treated as an ATT&CK mapping tool, but these references help explain why API flaws matter beyond isolated code bugs.

### CWE

The main implementation areas also map to CWE weakness categories:

- **CWE-89** - SQL Injection
- **CWE-287** - Improper Authentication
- **CWE-639** - Authorization Bypass Through User-Controlled Key
- **CWE-770** - Allocation of Resources Without Limits

These mappings make the repository more useful as a portfolio artifact because the scanner output can be described using recognized vulnerability language.

## Real-World Failure Patterns

### Case Study 1: The Parler Data Scrape (2021)

This case is included because it shows how predictable IDs and weak rate limiting can turn ordinary API behavior into large-scale data collection. The important design lesson is that public-looking data still needs access controls, deletion semantics, and abuse monitoring.

The failure pattern was a combination of:

1. Sequential post identifiers
2. Weak or missing throttling
3. Insufficient access restrictions
4. Data that remained accessible after users expected deletion

For my scanner design, this reinforces why ID predictability and rate limiting belong in the same conceptual document.

### Case Study 2: T-Mobile API Breach (2022)

This case is included because it represents the practical impact of object-level authorization failure at scale. When an API accepts customer identifiers without proving the caller is allowed to access that customer record, enumeration becomes a data-breach mechanism.

The relevant failure pattern was:

1. User or customer identifiers accepted as request parameters
2. Missing or insufficient object-level authorization
3. Inadequate throttling or monitoring
4. Large-scale scraping before detection

For this repository, the lesson is that authorization checks should be part of the data-access path, not an afterthought added only to certain routes.

## Design Review Questions

These questions are kept as repository review prompts, not as a tutorial quiz. They are useful checks for whether the scanner logic and documentation explain the important engineering decisions:

1. Why do UUIDs reduce enumeration risk without solving object-level authorization?
2. What is the difference between advertised rate-limit headers and active enforcement?
3. Why does time-based blind SQL injection require baseline timing instead of one request measurement?
4. Why should JWT validation use an explicit algorithm allowlist?

## Reference Material

These are the outside references that informed the project’s security model and terminology.

**Core references:**

- OWASP API Security Top 10 2023
- PortSwigger Web Security Academy labs on SQL injection, authentication, and authorization
- JWT.io for token structure and library behavior

**Deeper implementation references:**

- OWASP Testing Guide v4 sections on SQL injection methodology
- Auth0 JWT Handbook for JWT validation and token lifecycle design
- RFC 7519 for the JWT standard and security considerations

**Historical context:**

- Public writeups on OAuth and JWT implementation failures
- Research on token validation mistakes and timing issues
- API breach reports involving IDOR, weak rate limiting, and broken authentication
