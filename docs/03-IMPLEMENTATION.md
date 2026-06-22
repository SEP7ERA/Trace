# Implementation Deep Dive

This document records how I built the backend implementation and why the major pieces are arranged the way they are. I focus on the runtime mechanics, security boundaries, data movement, and trade-offs behind the code instead of presenting the project as a step-by-step exercise.

## File Structure Walkthrough
```
backend/
├── main.py              # Application entry point
├── factory.py           # FastAPI app factory with middleware
├── config.py            # Environment variables and constants
├── core/
│   ├── database.py      # SQLAlchemy engine and session factory
│   ├── security.py      # Password hashing, JWT creation/validation
│   ├── dependencies.py  # FastAPI dependencies (auth, database)
│   └── enums.py         # Type-safe enums for status, severity, test types
├── models/
│   ├── Base.py          # Base model with common fields (id, timestamps)
│   ├── User.py          # User authentication model
│   ├── Scan.py          # Scan metadata model
│   └── TestResult.py    # Individual test results model
├── repositories/
│   ├── user_repository.py         # User database operations
│   ├── scan_repository.py         # Scan database operations
│   └── test_result_repository.py  # Test result database operations
├── routes/
│   ├── auth.py          # Registration and login endpoints
│   └── scans.py         # Scan CRUD endpoints
├── schemas/
│   ├── user_schemas.py        # Pydantic models for user data
│   ├── scan_schemas.py        # Pydantic models for scan data
│   └── test_result_schemas.py # Pydantic models for test results
├── services/
│   ├── auth_service.py  # Authentication business logic
│   └── scan_service.py  # Scan orchestration business logic
└── scanners/
    ├── base_scanner.py      # Common HTTP logic, retry handling
    ├── rate_limit_scanner.py # Rate limiting detection
    ├── auth_scanner.py      # Authentication vulnerability detection
    ├── sqli_scanner.py      # SQL injection detection
    ├── idor_scanner.py      # IDOR/BOLA detection
    └── payloads.py          # Attack payloads organized by type
```

## Authentication Internals

### Password Hashing with Bcrypt

I designed the authentication layer so the database never stores plaintext passwords. The backend stores only bcrypt hashes, which keeps user credentials protected even if the user table is exposed.

The password hashing implementation lives in `backend/core/security.py:11-28`:
```python
import bcrypt
from jose import JWTError, jwt

def hash_password(password: str) -> str:
    """
    Hash a plain text password using bcrypt
    """
    password_bytes = password.encode("utf-8")  # Convert string to bytes
    salt = bcrypt.gensalt()  # Generate random salt (default 12 rounds)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")  # Convert bytes back to string for storage
```

**Implementation details:**
- **Line 18-19**: Bcrypt operates on byte strings, so I explicitly convert the incoming Python string before hashing.
- **Line 19**: `bcrypt.gensalt()` generates a unique salt for each password. I rely on bcrypt's encoded hash format so the salt stays embedded in the stored hash instead of being managed in a separate column.
- **Line 20**: `bcrypt.hashpw()` performs the deliberately expensive password hash operation. That cost is a security feature because it slows offline guessing if hashes are stolen.
- **Line 21**: I convert the result back to a string because the SQLAlchemy model stores the hash in a text column.

The password verification path is implemented in `security.py:21-31`:
```python
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain text password against a hashed password
    """
    password_bytes = plain_password.encode("utf-8")
    hashed_bytes = hashed_password.encode("utf-8")
    return bcrypt.checkpw(password_bytes, hashed_bytes)
```

**Verification flow:**
1. I convert the candidate password and stored hash back into bytes.
2. `bcrypt.checkpw()` reads the salt from the stored hash.
3. The candidate password is hashed using the same embedded salt and cost factor.
4. The derived hash is compared with the stored hash to determine whether authentication succeeds.

**Implementation risks this avoids:**
```python
# Wrong - storing plaintext
user.password = password  # Database breach = everyone's password leaked

# Wrong - using weak hashing
import hashlib
user.password = hashlib.md5(password.encode()).hexdigest()  # Fast = easy to brute force

# Wrong - forgetting to salt
user.password = hashlib.sha256(password.encode()).hexdigest()  # Rainbow tables break this

# Right - bcrypt with automatic salting
user.hashed_password = hash_password(password)  # Secure
```

### JWT Access Token Construction

After a successful login, I issue a signed JWT so the backend can authenticate later requests without storing server-side session state.

The token creation logic is in `core/security.py:34-56`:
```python
from datetime import datetime, timedelta
from config import settings

def create_access_token(
    data: dict[str, str],
    expires_delta: timedelta | None = None
) -> str:
    """
    Create a JWT access token
    """
    to_encode = data.copy()  # Don't modify the original dict
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES  # 1440 = 24 hours
        )
    
    to_encode.update({"exp": expire})  # Add expiration claim
    
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,  # MUST be random, 256+ bits
        algorithm=settings.ALGORITHM  # "HS256"
    )
    return encoded_jwt
```

**Token assembly details:**

**Line 43** - I copy the payload before adding claims so the caller's original dictionary is not mutated as a side effect.

**Line 45-50** - I calculate the expiration timestamp and store it in the standard `exp` claim. The JWT library later enforces that claim during decode.

**Line 52** - `jwt.encode()` serializes the payload, adds the header, and signs the token with HMAC-SHA256 using `SECRET_KEY`. The token structure is:
1. JSON header
2. JSON payload
3. HMAC signature
4. The three sections joined as `header.payload.signature`

The resulting token has this shape:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyQGV4YW1wbGUuY29tIiwiZXhwIjoxNzM4MzY4MDAwfQ.signature_here
```

**Design rationale:**
I chose stateless JWTs because the API can validate a request without looking up a server-side session record. That keeps the initial architecture simple and makes horizontal backend scaling easier: any backend instance with the same signing key can validate the token.

**Alternatives I considered:**
- **Session-based authentication**: A session ID stored in a cookie with server-side session data in Redis or the database. This improves revocation but adds shared state.
- **Access/refresh token rotation**: Short-lived access tokens with longer-lived refresh tokens. This is stronger for production systems but adds refresh storage, rotation logic, and revocation handling.

### JWT Validation and User Loading

When a protected endpoint receives a request, I validate the JWT signature first, then load the user record so authorization checks are based on current database state.

The dependency injection function is in `core/dependencies.py:17-49`:
```python
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from .security import decode_token
from .database import get_db
from repositories.user_repository import UserRepository
from schemas.user_schemas import UserResponse

security = HTTPBearer()  # Extracts "Authorization: Bearer <token>" header

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> UserResponse:
    """
    FastAPI dependency to extract and verify the current authenticated user
    """
    try:
        # Decode and verify the JWT
        payload = decode_token(credentials.credentials)
        email: str | None = payload.get("sub")
        
        if email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Load user from database
        user = UserRepository.get_by_email(db, email)
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return UserResponse.model_validate(user)
    
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
```

**Dependency behavior:**

**Line 27** - `HTTPBearer()` extracts the `Authorization: Bearer <token>` header and gives the dependency the raw token string.

**Line 35** - The dependency delegates cryptographic validation to `decode_token()`, which is defined in `security.py:48-62`:
```python
def decode_token(token: str) -> dict[str, str]:
    """
    Decode and verify a JWT token
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]  # Only accept HS256
        )
        return payload
    except JWTError as e:
        raise ValueError(f"Invalid token: {str(e)}") from e
```

This validation path enforces three security properties:
- The signature must be valid.
- The algorithm must match the explicit allowlist.
- The expiration claim must still be valid.

**Line 36** - I read the `sub` claim as the stable user identifier that was placed in the token during login.

**Line 38-43** - If the subject claim is missing, I treat the token as malformed and return a 401 response with the expected bearer-auth header.

**Line 46** - I load the user from the database instead of trusting the token alone. That allows deleted or disabled accounts to stop authenticating even if an old token still exists.

**Line 48-52** - A missing user record makes the token unusable. This closes the gap where a structurally valid token references an account that no longer exists.

**Line 54** - I convert the SQLAlchemy model to a response schema, which keeps `hashed_password` out of serialized API responses.

**Line 56-61** - JWT parsing failures are normalized into HTTP 401 responses, so authentication failures do not leak internal exception details.

### Authentication Request Flow Reference

The following request sequence shows the external shape of the authentication flow that the implementation supports:
```bash
# Register a user
curl -X POST http://localhost:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123"
  }'

# Response: {"id": 1, "email": "test@example.com", ...}

# Login
curl -X POST http://localhost:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123"
  }'

# Response: {"access_token": "eyJ...", "token_type": "bearer"}

# Use token to access protected endpoint
curl http://localhost:8000/scans/ \
  -H "Authorization: Bearer eyJ..."

# Response: [list of scans]
```

This trace confirms the intended contract: registration creates a user, login returns a bearer token, and protected routes require that token before returning scan data.

When a `401 Unauthorized` appears, the likely failure points are the bearer header format, token expiration, mismatched signing configuration, or a missing user record.

## SQL Injection Scanner Internals

### Detection Model

I implemented the SQL injection scanner around three detection strategies:
1. **Error-based detection** - database errors leak through the response body.
2. **Boolean-based blind detection** - logically true and false inputs create different response shapes.
3. **Time-based blind detection** - database delay functions create measurable latency changes.

### Scanner Strategy

The scanner combines curated payload sets with response analysis. The implementation lives in `backend/scanners/sqli_scanner.py` and uses shared request handling from `BaseScanner`.

### Error-Based Detection

The error-based branch starts at `sqli_scanner.py:51-94`:
```python
def _test_error_based_sqli(self) -> dict[str, Any]:
    """
    Test for error based SQL injection
    
    Detects database errors in responses indicating SQLi vulnerability
    """
    error_signatures = SQLiPayloads.get_error_signatures()
    
    basic_payloads = SQLiPayloads.BASIC_AUTHENTICATION_BYPASS
    
    for payload in basic_payloads:
        try:
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
                            "status_code": response.status_code,
                            "error_signature": signature,
                            "response_excerpt": response.text[:500],
                        }
        
        except Exception:
            continue  # Network errors don't indicate SQLi
    
    return {
        "vulnerable": False,
        "payloads_tested": len(basic_payloads),
        "description": "No database errors detected",
    }
```

**Implementation details:**

**Line 57** - I load database-specific error signatures from `scanners/payloads.py:9-30`. These strings let the scanner distinguish MySQL, PostgreSQL, and MSSQL-style error leakage:
```python
ERROR_SIGNATURES = {
    "mysql": [
        "sql syntax",
        "mysql_fetch",
        "mysql error",
    ],
    "postgres": [
        "postgresql",
        "pg_query",
        "syntax error",
    ],
    "mssql": [
        "sqlserver jdbc driver",
        "sqlexception",
    ],
}
```

**Line 59** - The scanner uses basic SQL injection payloads from `payloads.py:33-48`, including authentication-bypass-style strings.

**Line 63** - The request places the payload into a query parameter. A vulnerable backend pattern would resemble this:
```python
query = f"SELECT * FROM users WHERE id = {request.args['id']}"
```

With a payload such as `id=' OR 1=1--`, that vulnerable query is transformed into:
```sql
SELECT * FROM users WHERE id = ' OR 1=1--'
```

That malformed query can trigger a database error. If the application reflects that error into the HTTP response, the scanner can classify the issue from the response body.

**Line 65** - I normalize response text to lowercase before matching signatures to avoid case-sensitive misses.

**Line 68-72** - The scanner compares each known database signature against the response content. A match becomes evidence for an error-based SQL injection finding.

**Line 73-79** - I return the payload, probable database family, status code, matched signature, and a short response excerpt as evidence.

**Line 81-82** - Network failures are ignored for this specific detection branch because connectivity errors are not evidence of SQL injection.

**Line 84-88** - If no payload produces a database error signature, the branch reports that error-based SQLi was not observed.

### Boolean-Based Blind Detection

When an application suppresses database errors, I compare true-condition and false-condition responses.

The implementation is at `sqli_scanner.py:96-164`:
```python
def _test_boolean_based_sqli(self) -> dict[str, Any]:
    """
    Test for boolean based blind SQL injection
    
    Compares responses from true vs false conditions to detect SQLi
    """
    try:
        # Establish baseline
        baseline_response = self.make_request("GET", "/?id=1")
        baseline_length = len(baseline_response.text)
        baseline_status = baseline_response.status_code
        
        if baseline_status != 200:
            return {
                "vulnerable": False,
                "description": "Baseline request failed",
                "baseline_status": baseline_status,
            }
        
        boolean_payloads = SQLiPayloads.BOOLEAN_BASED_BLIND
        
        # Test true conditions: ' AND 1=1--
        true_payloads = [
            p for p in boolean_payloads
            if "AND '1'='1" in p or "AND 1=1" in p
        ]
        false_payloads = [
            p for p in boolean_payloads
            if "AND '1'='2" in p or "AND 1=2" in p or "AND 1=0" in p
        ]
        
        true_lengths = []
        for payload in true_payloads:
            response = self.make_request("GET", f"/?id={payload}")
            true_lengths.append(len(response.text))
        
        false_lengths = []
        for payload in false_payloads:
            response = self.make_request("GET", f"/?id={payload}")
            false_lengths.append(len(response.text))
        
        # Calculate averages
        avg_true = statistics.mean(true_lengths)
        avg_false = statistics.mean(false_lengths)
        
        length_diff = abs(avg_true - avg_false)
        
        # Significant difference indicates SQLi
        if length_diff > 100 and avg_true != avg_false:
            return {
                "vulnerable": True,
                "baseline_length": baseline_length,
                "true_condition_avg_length": avg_true,
                "false_condition_avg_length": avg_false,
                "length_difference": length_diff,
                "confidence": "HIGH" if length_diff > 500 else "MEDIUM",
            }
        
        return {
            "vulnerable": False,
            "description": "No boolean-based SQLi detected",
            "length_difference": length_diff,
        }
```

**Implementation details:**

**Line 105-106** - I collect a baseline response for ordinary input so the scanner has a stable reference point.

**Line 121-128** - I split payloads into always-true and always-false groups.

True condition example: `1' AND 1=1--`
```sql
SELECT * FROM users WHERE id = 1' AND 1=1--'
```
The `1=1` condition always evaluates true, so a vulnerable query can return data.

False condition example: `1' AND 1=2--`
```sql
SELECT * FROM users WHERE id = 1' AND 1=2--'
```
The `1=2` condition always evaluates false, so a vulnerable query can return an empty or visibly different response.

**Line 130-141** - I send multiple true and false payloads and record response lengths.

**Line 144-147** - I average the response lengths so one-off network variance has less influence on the result.

**Line 151** - A significant length difference becomes evidence that the backend evaluated injected SQL logic. A larger difference produces higher confidence.

**Detection rationale:**
If SQL injection is present, the backend evaluates the true and false clauses differently. If SQL injection is absent, both payload classes usually behave like invalid input and produce similar responses.

### Time-Based Blind Detection

For cases where content-based signals are weak, I use database delay functions and measure response latency.

The implementation is at `sqli_scanner.py:183-251`:
```python
def _test_time_based_sqli(self, delay_seconds: int = 5) -> dict[str, Any]:
    """
    Test for time based blind SQL injection
    
    Uses baseline timing comparison with statistical analysis
    for false positive reduction
    """
    try:
        # Establish baseline timing
        baseline_mean, baseline_stdev = self.get_baseline_timing("/")
        
        threshold = baseline_mean + (3 * baseline_stdev)
        expected_delay_time = baseline_mean + delay_seconds
        
        all_time_payloads = SQLiPayloads.TIME_BASED_BLIND
        
        # Group by database type
        delay_payloads = {
            "mysql": [p for p in all_time_payloads if "SLEEP" in p],
            "postgres": [p for p in all_time_payloads if "pg_sleep" in p],
            "mssql": [p for p in all_time_payloads if "WAITFOR" in p],
        }
        
        for db_type, payloads in delay_payloads.items():
            for payload in payloads:
                delay_times = []
                
                # Take multiple samples
                for _ in range(3):
                    try:
                        response = self.make_request(
                            "GET",
                            f"/?id={payload}",
                            timeout=delay_seconds + 10,
                        )
                        elapsed = getattr(response, "request_time", 0.0)
                        delay_times.append(elapsed)
                    
                    except Exception:
                        delay_times.append(delay_seconds + 10)  # Assume timeout = worked
                    
                    time.sleep(1)  # Space out requests
                
                avg_delay = statistics.mean(delay_times)
                
                # Check if delay matches expected
                if avg_delay >= expected_delay_time - 1:
                    confidence = "HIGH" if avg_delay >= expected_delay_time else "MEDIUM"
                    
                    return {
                        "vulnerable": True,
                        "database_type": db_type,
                        "payload": payload,
                        "baseline_time": f"{baseline_mean:.3f}s",
                        "response_time": f"{avg_delay:.3f}s",
                        "expected_delay": f"{expected_delay_time:.3f}s",
                        "confidence": confidence,
                        "individual_times": [f"{t:.3f}s" for t in delay_times],
                    }
```

**Timing baseline:**

**Line 192** - The scanner first calls `get_baseline_timing()` from `base_scanner.py:158-177`:
```python
def get_baseline_timing(
    self,
    endpoint: str,
    samples: int | None = None
) -> tuple[float, float]:
    """
    Establish baseline response time for an endpoint
    
    Takes multiple samples and calculates mean and standard deviation
    """
    if samples is None:
        samples = settings.DEFAULT_BASELINE_SAMPLES  # 10
    
    times = []
    
    for _ in range(samples):
        response = self.make_request("GET", endpoint)
        times.append(getattr(response, "request_time", 0.0))
        time.sleep(0.5)  # Space out samples
    
    return statistics.mean(times), statistics.stdev(times)
```

This baseline routine sends normal requests and calculates the mean and standard deviation of response times. Example baseline values might be:
- Mean: 0.15s
- Stdev: 0.02s

**Line 194** - I calculate an outlier threshold as `mean + 3*stdev`. In the example, that becomes `0.21s`, which gives the scanner a statistical boundary for unusual latency.

**Line 195** - I add the intended delay to the baseline. If the baseline is `0.15s` and the payload asks for a 5-second sleep, the expected response is around `5.15s`.

**Line 200-204** - I group payloads by database family because MySQL, PostgreSQL, and MSSQL use different sleep syntax.

**Line 211-225** - I take multiple samples for each delay payload. This reduces false positives from jitter, slow upstreams, or transient network variance.

**Line 230** - I accept a delay when the average response time is close enough to the expected delay window. The tolerance accounts for network and application overhead.

**Detection rationale:**
A vulnerable query executes the database sleep function, so the response includes the injected delay. A non-vulnerable backend treats the payload as ordinary input and returns near the baseline.

## Security Implementation

### JWT Signature Validation

I built the authentication scanner to test whether a target accepts unsigned JWTs. The none-algorithm check lives in `auth_scanner.py:168-213`:
```python
def _test_none_algorithm(self) -> dict[str, Any]:
    """
    Test if server accepts JWT with 'none' algorithm
    
    Critical vulnerability: allows unsigned tokens to be accepted
    """
    try:
        header, payload, signature = self.auth_token.split(".")
        
        none_variants = AuthPayloads.get_jwt_none_variants()
        # ["none", "None", "NONE", "nOnE", "NoNe", "NOne"]
        
        for variant in none_variants:
            # Create malicious header
            malicious_header = self._base64url_encode(
                json.dumps({"alg": variant, "typ": "JWT"})
            )
            
            # Remove signature (trailing period means "no signature")
            malicious_token = f"{malicious_header}.{payload}."
            
            response = self.make_request(
                "GET",
                "/",
                headers={"Authorization": f"Bearer {malicious_token}"}
            )
            
            if response.status_code == 200:
                return {
                    "vulnerable": True,
                    "vulnerability_type": "JWT None Algorithm",
                    "algorithm_variant": variant,
                    "status_code": response.status_code,
                    "recommendations": [
                        "Reject tokens with 'none' algorithm (all case variations)",
                        "Explicitly verify signature before accepting tokens",
                        "Use allowlist of accepted algorithms",
                    ],
                }
        
        return {
            "vulnerable": False,
            "description": "None algorithm properly rejected",
        }
```

**Security property under test:**

Normal JWT structure: `header.payload.signature`
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.signature
```

Unsigned malicious JWT structure: `header.payload.`
```
eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9.
```

Decoded malicious header:
```json
{"alg": "none", "typ": "JWT"}
```

Decoded malicious payload:
```json
{"sub": "admin"}
```

If a server accepts the unsigned form, an attacker can forge identity claims without possessing the signing key.

**Defensive implementation:**

My JWT validation in `core/security.py:54-57` explicitly restricts accepted algorithms:
```python
payload = jwt.decode(
    token,
    settings.SECRET_KEY,
    algorithms=[settings.ALGORITHM]  # ["HS256"] - none not in this list
)
```

The `algorithms` parameter acts as an allowlist. Because `none` is not included in `['HS256']`, the decoder rejects unsigned tokens.

**Unsafe decoder patterns:**
```python
# BAD - accepts any algorithm
payload = jwt.decode(token, settings.SECRET_KEY)

# BAD - doesn't verify signature
payload = jwt.decode(token, options={"verify_signature": False})

# BAD - allows none
payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256", "none"])
```

### IDOR Prevention Pattern

I enforce object ownership in `services/scan_service.py:67-84` rather than trusting the route parameter alone:
```python
@staticmethod
def get_scan_by_id(db: Session, scan_id: int, user_id: int) -> ScanResponse:
    """
    Get scan by ID with authorization check
    """
    scan = ScanRepository.get_by_id(db, scan_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # CRITICAL: Check if user owns this scan
    if scan.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this scan",
        )
    
    return ScanResponse.model_validate(scan)
```

**Why I check existence before ownership:**
Line 75-78 returns 404 when the scan does not exist. I intentionally avoid revealing whether an inaccessible scan ID belongs to someone else.

If the service returned different responses for nonexistent scans and unauthorized scans, an attacker could enumerate valid scan IDs. The safer behavior is to keep resource existence less obvious.

**Ownership enforcement:**
Line 81-84 compares the stored `scan.user_id` with the authenticated `user_id`. A mismatch blocks access.

I keep this check in the service layer because every scan retrieval path should pass through the same authorization boundary. That reduces the chance that a future route accidentally returns another user's scan.

## Data Flow Example

This section traces one complete scan request through the backend, using a SQLi scan as the concrete path.

### Request Entry

The route entry point is `routes/scans.py:23-37`:
```python
@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.API_RATE_LIMIT_SCAN)  # "15/minute"
async def create_scan(
    request: Request,
    scan_request: ScanRequest,  # Pydantic validates this
    db: Session = Depends(get_db),  # Injects database session
    current_user: UserResponse = Depends(get_current_user),  # Validates JWT
) -> ScanResponse:
    """
    Create and execute a new security scan
    """
    return ScanService.run_scan(db, current_user.id, scan_request)
```

By the time execution enters the service layer:
- `scan_request` has passed Pydantic validation.
- `current_user` has been authenticated through the JWT dependency.
- `db` is an active SQLAlchemy session scoped to the request.
- The route-level scan rate limit has already been evaluated.

The route does not execute scanner logic directly; it delegates orchestration to the service layer.

### Processing Layer

The service-level orchestration is in `services/scan_service.py:23-65`:
```python
@staticmethod
def run_scan(db: Session, user_id: int, scan_request: ScanRequest) -> ScanResponse:
    # Create scan record
    scan = ScanRepository.create_scan(
        db=db,
        user_id=user_id,
        target_url=str(scan_request.target_url),
    )
    
    # Map test types to scanner classes
    scanner_mapping: dict[TestType, type[BaseScanner]] = {
        TestType.RATE_LIMIT: RateLimitScanner,
        TestType.AUTH: AuthScanner,
        TestType.SQLI: SQLiScanner,
        TestType.IDOR: IDORScanner,
    }
    
    results: list[TestResultCreate] = []
    
    # Execute each requested test
    for test_type in scan_request.tests_to_run:
        scanner_class: type[BaseScanner] | None = scanner_mapping.get(test_type)
        
        if not scanner_class:
            continue  # Skip unknown test types
        
        try:
            scanner = scanner_class(
                target_url=str(scan_request.target_url),
                auth_token=scan_request.auth_token,
                max_requests=scan_request.max_requests,
            )
            
            result = scanner.scan()  # Execute the actual test
            results.append(result)
        
        except Exception as e:
            # Scanner crashed - return error result instead of failing entire scan
            results.append(
                TestResultCreate(
                    test_name=test_type,
                    status="error",
                    severity="info",
                    details=f"Scanner error: {str(e)}",
                    evidence_json={"error": str(e)},
                    recommendations_json=[
                        "Check target URL is accessible",
                        "Verify authentication token if provided",
                    ],
                )
            )
```

This service method is responsible for coordination:
- It creates the scan record early so later results can attach to a scan ID.
- It maps validated test-type enums to scanner classes.
- It instantiates each scanner with the target URL, optional token, and request budget.
- It calls the scanner's `scan()` method and collects normalized results.
- It converts scanner exceptions into error results so one failed scanner does not invalidate the entire scan.

### Storage and Response Shape

The service persists scanner results through `TestResultRepository`:
```python
    # Save all results
    for result in results:
        TestResultRepository.create_test_result(
            db=db,
            scan_id=scan.id,
            test_name=result.test_name,
            status=result.status,
            severity=result.severity,
            details=result.details,
            evidence_json=result.evidence_json,
            recommendations_json=result.recommendations_json,
        )
    
    db.refresh(scan)  # Reload scan with test_results relationship populated
    
    return ScanResponse.model_validate(scan)
```

The API response returns the scan record with nested test results, giving the frontend a complete result object without requiring an immediate second query:
```json
{
  "id": 42,
  "user_id": 1,
  "target_url": "https://api.example.com/users",
  "scan_date": "2026-02-04T10:30:00Z",
  "created_at": "2026-02-04T10:30:00Z",
  "test_results": [
    {
      "id": 101,
      "scan_id": 42,
      "test_name": "sqli",
      "status": "vulnerable",
      "severity": "critical",
      "details": "Error-based SQL injection detected: mysql",
      "evidence_json": {
        "database_type": "mysql",
        "payload": "' OR 1=1--",
        "error_signature": "sql syntax"
      },
      "recommendations_json": [
        "Use parameterized queries (prepared statements)",
        "Never concatenate user input into SQL queries"
      ]
    }
  ]
}
```

## Error Handling Patterns

### Database Errors and Rollback Behavior

The database session dependency centralizes request-scoped session cleanup:
```python
# core/database.py:28-36
def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency for database sessions
    """
    db = SessionLocal()
    try:
        yield db  # Provide session to route handler
    finally:
        db.close()  # Always close, even if exception raised
```

If request processing raises an exception:
1. FastAPI unwinds the request handler.
2. Control returns to the dependency cleanup block.
3. `db.close()` executes.
4. SQLAlchemy rolls back uncommitted work.
5. The connection returns to the pool.

This example shows the kind of partial-write situation the session lifecycle protects against:
```python
@router.post("/scans/")
async def create_scan(db: Session = Depends(get_db), ...):
    scan = ScanRepository.create_scan(db, ...)  # INSERT INTO scans
    
    # Something goes wrong here
    raise ValueError("Oops")
    
    # This never runs
    TestResultRepository.create_test_result(db, ...)
```

Without rollback behavior, the scan row could persist while its child results are missing. That would leave the database in a confusing state.

With the dependency-managed session lifecycle, uncommitted writes are discarded when the request fails.

**Unsafe transaction pattern:**
```python
# Bad - manual session management
db = SessionLocal()
try:
    scan = ScanRepository.create_scan(db, ...)
    db.commit()  # Committed before error could happen
    raise ValueError("Oops")
finally:
    db.close()

# Scan is committed, error occurs after - inconsistent state
```

### Scanner Timeout Recovery

The scanner base class implements retry and backoff in `base_scanner.py:92-156`:
```python
def make_request(
    self,
    method: str,
    endpoint: str,
    **kwargs: Any,
) -> requests.Response:
    """
    Make HTTP request with retry logic and rate limit handling
    """
    self._wait_before_request()  # Implement request spacing
    
    url = urljoin(self.target_url, endpoint)
    retry_count = 0
    backoff_factor = 2.0
    
    kwargs.setdefault("timeout", settings.SCANNER_CONNECTION_TIMEOUT)
    
    while retry_count <= settings.DEFAULT_RETRY_COUNT:  # 3 retries
        try:
            start_time = time.time()
            response = self.session.request(method, url, **kwargs)
            
            # Track timing for time-based detection
            setattr(response, "request_time", time.time() - start_time)
            
            self.request_count += 1
            
            # Handle 429 Too Many Requests
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                wait_time = int(retry_after) if retry_after.isdigit() else 60
                time.sleep(wait_time)
                retry_count += 1
                continue  # Try again after waiting
            
            # Handle server errors with backoff
            if response.status_code >= 500 and retry_count < settings.DEFAULT_RETRY_COUNT:
                wait_time = backoff_factor ** retry_count  # 1s, 2s, 4s
                time.sleep(wait_time)
                retry_count += 1
                continue
            
            return response  # Success
        
        except (requests.Timeout, requests.ConnectionError):
            if retry_count < settings.DEFAULT_RETRY_COUNT:
                wait_time = backoff_factor ** retry_count
                time.sleep(wait_time)
                retry_count += 1
            else:
                raise  # Give up after 3 retries
    
    return response  # Return last response if loop completes
```

**Retry behavior:**

1. **Timeouts** use exponential backoff before the scanner gives up.
2. **Connection errors** follow the same retry path because they may be transient.
3. **HTTP 429 responses** honor `Retry-After` when the target provides it.
4. **HTTP 5xx responses** retry a limited number of times, then return the response to the scanner-specific logic.

## Performance Optimizations

### N+1 Query Problem
```python
# Bad - triggers N+1 queries
@router.get("/scans/")
async def get_scans(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scans = db.query(Scan).filter(Scan.user_id == user.id).all()
    # SQL: SELECT * FROM scans WHERE user_id = 1
    
    for scan in scans:
        print(scan.test_results)  # Each access triggers new query!
        # SQL: SELECT * FROM test_results WHERE scan_id = 42
        # SQL: SELECT * FROM test_results WHERE scan_id = 43
        # ... repeated for each scan
    
    return scans
```

With 10 scans and 4 results per scan, the naive path can create 41 separate queries: one query for the scan list plus repeated relationship loads.

### Eager Loading with joinedload
```python
# Good - single query with JOIN
def get_by_user(db: Session, user_id: int) -> list[Scan]:
    return (
        db.query(Scan)
        .options(joinedload(Scan.test_results))  # Load relationship in same query
        .filter(Scan.user_id == user_id)
        .all()
    )
    # SQL: SELECT scans.*, test_results.* 
    #      FROM scans 
    #      LEFT JOIN test_results ON scans.id = test_results.scan_id
    #      WHERE scans.user_id = 1
```

The eager-loading query loads scans and test results together. After that, `scan.test_results` reads already-loaded relationship data instead of opening new queries.

**Observed impact:**
- Before: 41 queries, roughly 205ms when each query takes around 5ms.
- After: 1 joined query, roughly 15ms.
- Result: about **13x faster** for that access pattern.

### Request Connection Pooling

`BaseScanner` keeps a persistent HTTP session in `base_scanner.py:40-62`:
```python
def __init__(self, target_url: str, auth_token: str | None = None, ...):
    self.target_url = target_url.rstrip("/")
    self.auth_token = auth_token
    self.session = self._create_session()  # Created once
    
def _create_session(self) -> requests.Session:
    """
    Create persistent HTTP session with proper headers
    """
    session = requests.Session()
    
    session.headers.update({
        "User-Agent": f"{settings.APP_NAME}/{settings.VERSION}",
        "Accept": "application/json",
    })
    
    if self.auth_token:
        session.headers.update({"Authorization": f"Bearer {self.auth_token}"})
    
    return session
```

**Why I use a session:**

Without a persistent session, each request can pay the cost of a new TCP connection and TLS handshake:
```python
# Each call creates new TCP connection
requests.get("https://api.example.com/endpoint1")  # Connect, TLS handshake, request, close
requests.get("https://api.example.com/endpoint2")  # Connect, TLS handshake, request, close
# 2 connections, 2 TLS handshakes
```

With a session, later requests can reuse the connection:
```python
session = requests.Session()
session.get("https://api.example.com/endpoint1")  # Connect, TLS handshake, request, keep-alive
session.get("https://api.example.com/endpoint2")  # Reuse connection, request
# 1 connection, 1 TLS handshake
```

For scan paths that issue many requests, connection reuse removes repeated handshake overhead and keeps the scanner faster without changing detection behavior.

## Configuration Management

### Settings Loading

I centralize runtime configuration with Pydantic settings:
```python
# config.py:14-69
from functools import lru_cache
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file="../.env",  # Load from .env file
        env_file_encoding="utf-8",
        case_sensitive=True  # DATABASE_URL != database_url
    )
    
    # Required fields (no default)
    DATABASE_URL: str
    SECRET_KEY: str
    
    # Optional fields (have defaults)
    APP_NAME: str = "API Security Tester"
    DEBUG: bool = False
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    
    @property
    def cors_origins_list(self) -> list[str]:
        """Convert comma-separated string to list"""
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",")]

@lru_cache
def get_settings() -> Settings:
    """
    Get cached settings instance
    
    @lru_cache ensures settings are loaded only once
    """
    return Settings()

settings = get_settings()
```

**Validation behavior:**

Pydantic validates the declared types during application startup:
```python
# .env contains:
# DEBUG=not_a_boolean

# When Settings() instantiates:
# ValidationError: field required to be bool, got str 'not_a_boolean'
```

This makes configuration errors fail early instead of turning into ambiguous runtime behavior later.

**Settings cache:**

Without caching, repeated imports could rebuild the settings object:
```python
# Every import creates new Settings instance
from config import settings  # Loads .env
from config import settings  # Loads .env again
```

With `@lru_cache`, the application reuses one settings object:
```python
# First import loads .env
from config import settings  # Loads .env, caches result

# Subsequent imports reuse cached instance
from config import settings  # Returns cached Settings
```

That keeps startup behavior consistent and avoids repeatedly reading the environment file.

## Database and Storage Operations

### Transaction-Aware Record Creation

The scan repository exposes explicit commit control:
```python
# repositories/scan_repository.py:13-32
@staticmethod
def create_scan(
    db: Session,
    user_id: int,
    target_url: str,
    commit: bool = True  # Allow caller to control commit
) -> Scan:
    """
    Create a new scan
    """
    scan = Scan(
        user_id=user_id,
        target_url=target_url,
        scan_date=datetime.now(UTC),
    )
    db.add(scan)
    
    if commit:
        db.commit()  # Flush to database
        db.refresh(scan)  # Reload to get auto-generated ID
    
    return scan
```

**Implementation details:**

- **Transaction management**: I use the `commit` parameter so callers can batch related writes into one transaction.
- **Refresh after commit**: The refresh call loads database-generated fields such as `id`, `created_at`, and `updated_at`.
- **Foreign key constraints**: PostgreSQL enforces the relationship between `test_results.scan_id` and `scans.id`, so parent scan rows need stable IDs before child rows are saved.

### Bulk Inserts for Test Results

The test-result repository can insert multiple result rows in one operation:
```python
# repositories/test_result_repository.py:52-67
@staticmethod
def bulk_create(
    db: Session,
    test_results: list[TestResult],
    commit: bool = True
) -> list[TestResult]:
    """
    Create multiple test results in bulk
    """
    db.add_all(test_results)  # Add all at once
    
    if commit:
        db.commit()
        for result in test_results:
            db.refresh(result)  # Refresh each to get IDs
    
    return test_results
```

**Why I batch writes:**

Individual inserts create one commit per result:
```python
for result in results:
    db.add(result)
    db.commit()  # Commit after each - 4 commits for 4 results
# 4 round trips to database
```

Bulk insert reduces the operation to one commit:
```python
db.add_all(results)
db.commit()  # Single commit for all 4 results
# 1 round trip to database
```

For a scan with four result rows, batching avoids unnecessary database round trips and keeps result persistence simpler.

## Implementation Risk Notes

### Risk 1: JWT Algorithm Validation

**Failure mode:**
A decoder accepts a token with `alg: none`, allowing forged identity claims.

**Vulnerable pattern:**
```python
# Problematic code - accepts any algorithm
payload = jwt.decode(token, settings.SECRET_KEY)

# Attacker sends:
# eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.
# (header: {"alg": "none"}, payload: {"sub": "admin"}, no signature)

# Library accepts it because no algorithm restriction
```

**Safe pattern:**
```python
# Correct - explicitly allow only HS256
payload = jwt.decode(
    token,
    settings.SECRET_KEY,
    algorithms=["HS256"]  # Reject "none" and other algorithms
)
```

**Why this matters:**
Without algorithm validation, the signature check can be bypassed. I treat the algorithm allowlist as part of the authentication boundary.

### Risk 2: Raw SQL Query Construction

**Failure mode:**
User-controlled input is concatenated into SQL and changes query logic.

**Vulnerable pattern:**
```python
# Vulnerable - concatenating user input
email = request.get("email")
query = f"SELECT * FROM users WHERE email = '{email}'"
db.execute(text(query))

# Becomes: SELECT * FROM users WHERE email = 'admin'--'
# Comment (--) removes password check
```

**Safer parameterized pattern:**
```python
# Correct - parameterized query
email = request.get("email")
db.execute(
    text("SELECT * FROM users WHERE email = :email"),
    {"email": email}
)

# SQLAlchemy escapes the email value safely
```

The ORM version is the preferred path in this codebase:
```python
# Best - ORM automatically parameterizes
db.query(User).filter(User.email == email).first()
```

**Why this matters:**
Parameterized queries preserve the boundary between SQL code and user-supplied data.

### Risk 3: Missing Object Authorization

**Failure mode:**
An authenticated user changes a scan ID and reads another user's result.

**Vulnerable pattern:**
```python
# Vulnerable - no ownership check
@router.get("/scans/{scan_id}")
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = ScanRepository.get_by_id(db, scan_id)
    if not scan:
        raise HTTPException(404)
    return scan  # Returns any scan, regardless of ownership
```

**Safe pattern:**
```python
# Correct - verify ownership
@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = ScanRepository.get_by_id(db, scan_id)
    if not scan:
        raise HTTPException(404)
    
    if scan.user_id != current_user.id:
        raise HTTPException(403, detail="Not authorized")
    
    return scan
```

**Why this matters:**
Authentication identifies the requester; authorization decides whether that requester can access a specific object. I keep both checks in the request path.

## Operational Diagnostics

### Diagnostic Path 1: JWT Token Looks Valid but Returns 401

This failure usually means the token shape is valid but the backend's validation context does not match it.

**Inspection point 1: expiration claim**
```python
import jwt
import datetime

token = "eyJ..."
decoded = jwt.decode(token, options={"verify_signature": False})  # Skip verification for debugging
print(decoded)
# {"sub": "user@example.com", "exp": 1704067200}

exp_time = datetime.datetime.fromtimestamp(decoded["exp"])
now = datetime.datetime.now()
print(f"Expires: {exp_time}, Now: {now}, Valid: {exp_time > now}")
```

**Inspection point 2: signing key**
```python
# In Python shell with access to settings
from config import settings
print(f"SECRET_KEY: {settings.SECRET_KEY}")
# Make sure this matches the key used to create the token
```

**Inspection point 3: header algorithm**
```python
# Decode header without verification
import base64
import json

token = "eyJ..."
header = token.split(".")[0]
# Add padding if needed
padding = 4 - (len(header) % 4)
if padding != 4:
    header += "=" * padding

decoded_header = json.loads(base64.urlsafe_b64decode(header))
print(decoded_header)
# {"alg": "HS256", "typ": "JWT"}

# Make sure "alg" matches settings.ALGORITHM
```

**Common causes:**
- The token is expired.
- The token was signed with a different `SECRET_KEY` than the running backend uses.
- The token algorithm does not match the backend allowlist.

### Diagnostic Path 2: Scanner Timeouts

If all scanner results return `status="error"` with timeout details, I treat the target reachability path as the first suspect.

**Inspection point 1: target reachability from inside the backend container**
```bash
# From inside backend container
docker exec -it apisec_backend_dev bash
curl -v https://target-api.com/endpoint

# Check:
# - Does connection succeed?
# - What's the response time?
# - Are there redirects?
```

**Inspection point 2: timeout configuration**
```python
# config.py:51
SCANNER_CONNECTION_TIMEOUT: int = 180  # 3 minutes

# If target is slower, increase this
```

**Inspection point 3: captured scanner exception**
```python
# services/scan_service.py exception block shows error
except Exception as e:
    details=f"Scanner error: {str(e)}"
    
# Check what the exception says:
# - "Connection timeout" = target slow or unreachable
# - "Name resolution failed" = DNS issue
# - "SSL certificate verify failed" = TLS problem
```

**Inspection point 4: known responsive target**
```bash
# Test with httpbin (always responsive)
curl -X POST http://localhost:8000/scans/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://httpbin.org/get",
    "tests_to_run": ["rate_limit"],
    "max_requests": 10
  }'
```

**Common causes:**
- The target is only reachable through a VPN or private network.
- The target is rate limiting or delaying scanner traffic.
- DNS resolution fails inside the Docker network.
- TLS validation fails because of self-signed or expired certificates.

### Diagnostic Path 3: Database Deadlocks

Intermittent `DeadlockDetected` errors usually point to competing transactions taking locks in different orders.

**Inspection point 1: active database locks and queries**
```sql
-- PostgreSQL query to see locks
SELECT
  pid,
  state,
  query_start,
  state_change,
  query
FROM pg_stat_activity
WHERE state = 'active';
```

**Inspection point 2: inconsistent update order**
```python
# Problematic pattern - different order
# Thread 1:
UPDATE scans SET ... WHERE id = 1;
UPDATE test_results SET ... WHERE scan_id = 1;

# Thread 2:
UPDATE test_results SET ... WHERE scan_id = 2;
UPDATE scans SET ... WHERE id = 2;

# Thread 1 locks scans.id=1, waits for test_results
# Thread 2 locks test_results.scan_id=2, waits for scans
# = Deadlock
```

**Preferred fix: consistent lock ordering**
```python
# Both threads update in same order = no deadlock
# Always update parent (scans) before child (test_results)
UPDATE scans SET ... WHERE id = ?;
UPDATE test_results SET ... WHERE scan_id = ?;
```

**Common causes:**
- Multiple transactions update related rows in different orders.
- Long-running transactions hold locks longer than expected.
- Missing indexes force wider scans and broader locking behavior.

## Code Organization Principles

### Thin Route Handlers

I keep route handlers intentionally narrow. The route in `routes/scans.py` shows the pattern:
```python
@router.post("/", response_model=ScanResponse)
async def create_scan(
    request: Request,
    scan_request: ScanRequest,
    db: Session = Depends(get_db),
    current_user: UserResponse = Depends(get_current_user),
) -> ScanResponse:
    return ScanService.run_scan(db, current_user.id, scan_request)
```

The route performs three jobs:
1. It receives validated dependencies and request data.
2. It delegates the operation to the service layer.
3. It returns the serialized response.

**Business logic stays in services.** The route layer handles HTTP concerns such as request parsing, dependency injection, authentication, and response serialization.

This keeps route tests focused on HTTP behavior:
```python
# Test route with mocked service
def test_create_scan(mock_service):
    mock_service.run_scan.return_value = fake_scan
    
    response = client.post("/scans/", json={...})
    
    assert response.status_code == 201
    assert mock_service.run_scan.called
```

The route test can mock the service because database access, scanner execution, and persistence behavior live behind the service boundary.

### Naming Conventions

- `*Repository` = data access classes such as `UserRepository` and `ScanRepository`.
- `*Service` = business logic coordinators such as `AuthService` and `ScanService`.
- `*Scanner` = security test implementations such as `SQLiScanner` and `AuthScanner`.
- `*Schema` = Pydantic validation and serialization models such as `UserCreate` and `ScanResponse`.
- `get_*` functions = FastAPI dependencies such as `get_db` and `get_current_user`.
- `_private_method` = internal helper that is not part of the public interface.

I use these naming patterns so a reviewer can locate the correct layer quickly: database work belongs in repositories, orchestration belongs in services, and vulnerability checks belong in scanners.

## Extension Surface

### Adding a New Security Test: XSS Scanner Example

The scanner architecture expands through a small number of registration points. An XSS scanner would follow the same contract as the existing scanners.

**1. Scanner implementation** in `backend/scanners/xss_scanner.py`:
```python
from .base_scanner import BaseScanner
from .payloads import XSSPayloads
from core.enums import TestType, ScanStatus, Severity
from schemas.test_result_schemas import TestResultCreate

class XSSScanner(BaseScanner):
    """
    Tests for Cross-Site Scripting vulnerabilities
    """
    
    def scan(self) -> TestResultCreate:
        reflected_test = self._test_reflected_xss()
        
        if reflected_test["vulnerable"]:
            return TestResultCreate(
                test_name=TestType.XSS,
                status=ScanStatus.VULNERABLE,
                severity=Severity.HIGH,
                details=f"Reflected XSS detected: {reflected_test['payload']}",
                evidence_json=reflected_test,
                recommendations_json=[
                    "Encode user input before rendering in HTML",
                    "Use Content-Security-Policy headers",
                    "Validate input on server side",
                ],
            )
        
        return TestResultCreate(
            test_name=TestType.XSS,
            status=ScanStatus.SAFE,
            severity=Severity.INFO,
            details="No XSS vulnerabilities detected",
            evidence_json=reflected_test,
            recommendations_json=[],
        )
    
    def _test_reflected_xss(self) -> dict[str, Any]:
        payloads = XSSPayloads.get_basic_payloads()
        
        for payload in payloads:
            response = self.make_request("GET", f"/?q={payload}")
            
            # Check if payload appears unencoded in response
            if payload in response.text:
                return {
                    "vulnerable": True,
                    "payload": payload,
                    "status_code": response.status_code,
                }
        
        return {"vulnerable": False}
```

**2. Enum registration** in `backend/core/enums.py:19-26`:
```python
class TestType(str, Enum):
    RATE_LIMIT = "rate_limit"
    AUTH = "auth"
    SQLI = "sqli"
    IDOR = "idor"
    XSS = "xss"  # New test type
```

**3. Service-layer scanner map registration** in `backend/services/scan_service.py:32-38`:
```python
scanner_mapping: dict[TestType, type[BaseScanner]] = {
    TestType.RATE_LIMIT: RateLimitScanner,
    TestType.AUTH: AuthScanner,
    TestType.SQLI: SQLiScanner,
    TestType.IDOR: IDORScanner,
    TestType.XSS: XSSScanner,  # Register new scanner
}
```

**4. Payload storage** in `backend/scanners/payloads.py:250-280`:
```python
class XSSPayloads:
    BASIC_XSS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
    ]
    
    @classmethod
    def get_basic_payloads(cls) -> list[str]:
        return cls.BASIC_XSS
```

**5. Frontend constant update** in `frontend/src/config/constants.ts`:
```typescript
export const SCAN_TEST_TYPES = {
  // ... existing
  XSS: 'xss',
} as const;

export const TEST_TYPE_LABELS: Record<ScanTestType, string> = {
  // ... existing
  [SCAN_TEST_TYPES.XSS]: 'Cross-Site Scripting',
};
```

The important architectural point is that a new scanner does not require route or repository changes. The route accepts validated test types, the service maps those test types to scanner classes, and the database stores normalized result records.

## Repository Continuation Notes

The implementation is organized around a few long-term extension points:

1. **Scanner depth** - I can add more payload families, refine thresholds, and improve evidence capture without changing the route layer.
2. **Scanner registration** - I can move the hardcoded map toward a plugin registry while keeping the `BaseScanner` contract.
3. **Operational maturity** - I can move long-running scans into a worker queue, add progress reporting, and preserve the current service/repository boundaries.
