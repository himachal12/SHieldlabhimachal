"""
Fix Generation Prompt Templates
One template per "fixable" vulnerability category. Each template anchors
the model with a concrete example of vulnerable -> fixed so output is
consistent rather than the model improvising a different style every time.
"""

# Shared instruction block appended to every category prompt
OUTPUT_FORMAT_INSTRUCTIONS = """
CRITICAL REQUIREMENT FOR fixed_code:
- Replace ONLY the exact lines shown in the vulnerable code above
- Do NOT add new functions, classes, or imports outside of what's shown
- The fix must be a direct drop-in replacement for the vulnerable code
- Match the indentation of the original code exactly
- If you need an import, add it inline (e.g. "import subprocess\\nresult = ...")
  NOT as a separate top-level import block

Respond with ONLY valid JSON, no markdown fences, no extra commentary:
{{
  "fixed_code": "the corrected code as a direct replacement for the vulnerable snippet",
  "why_vulnerable": "one sentence explaining the specific risk",
  "why_fix_works": "one sentence explaining why the fix resolves it",
  "remediation_time": "estimate like '15 minutes' or '1 hour'"
}}
"""

TEMPLATES = {

    "SQL Injection": """You are a senior security engineer fixing a SQL injection vulnerability.

VULNERABLE CODE:
{code}

CONTEXT: This code builds a SQL query using string formatting/concatenation with
unsanitized input, allowing attackers to inject arbitrary SQL.

REQUIREMENTS:
- Convert to a parameterized query (using ? or %s placeholders, NOT f-strings or .format())
- Preserve the original variable names and overall logic
- Do not change unrelated code

EXAMPLE TRANSFORMATION:
  Before: query = f"SELECT * FROM users WHERE id = {{user_id}}"
          cursor.execute(query)
  After:  query = "SELECT * FROM users WHERE id = ?"
          cursor.execute(query, (user_id,))
""" + OUTPUT_FORMAT_INSTRUCTIONS,

    "Hardcoded Secrets": """You are a senior security engineer fixing a hardcoded secret.

VULNERABLE CODE:
{code}

CONTEXT: A secret (API key, password, token) is hardcoded directly in source code,
where it could be exposed via version control or code leaks.

REQUIREMENTS:
- Move the secret to an environment variable using os.environ.get()
- Provide a safe placeholder/None default, not a real-looking fake value
- Preserve the original variable name

EXAMPLE TRANSFORMATION:
  Before: API_KEY = "sk_live_abc123xyz"
  After:  API_KEY = os.environ.get("API_KEY")  # set in .env, never commit real keys
""" + OUTPUT_FORMAT_INSTRUCTIONS,

    "Weak Cryptography": """You are a senior security engineer fixing weak cryptographic usage.

VULNERABLE CODE:
{code}

CONTEXT: This code uses a cryptographically broken or unsuitable algorithm
(MD5/SHA1 for passwords, ECB cipher mode, etc.) that is vulnerable to
collision attacks or trivial brute-forcing.

REQUIREMENTS:
- If this is password hashing: replace with bcrypt (preferred) or werkzeug's
  generate_password_hash/check_password_hash
- If this is general hashing (not passwords): use hashlib.sha256 at minimum
- Preserve the original function's input/output contract (still takes a string,
  still returns something usable for storage/comparison)

EXAMPLE TRANSFORMATION:
  Before: def hash_password(password):
              return hashlib.md5(password.encode()).hexdigest()
  After:  from werkzeug.security import generate_password_hash
          def hash_password(password):
              return generate_password_hash(password)
""" + OUTPUT_FORMAT_INSTRUCTIONS,

    "Command Injection": """You are a senior security engineer fixing a command injection vulnerability.

VULNERABLE CODE:
{code}

CONTEXT: User input is passed into a shell command (os.system, subprocess with
shell=True, etc.), allowing attackers to inject arbitrary shell commands.

REQUIREMENTS:
- Use subprocess.run() with a list of arguments (NOT a string), and shell=False
- Never pass user input through a shell interpreter
- If the use case is genuinely simple (e.g. ping a host), validate/sanitize
  the input format first (e.g. regex-match a valid hostname/IP) as defense in depth

EXAMPLE TRANSFORMATION:
  Before: os.system(f"ping -c 1 {{host}}")
  After:  subprocess.run(["ping", "-c", "1", host], shell=False, timeout=5)
""" + OUTPUT_FORMAT_INSTRUCTIONS,

    "Insecure Deserialization": """You are a senior security engineer fixing an insecure deserialization vulnerability.

VULNERABLE CODE:
{code}

CONTEXT: This code deserializes untrusted data using pickle (or similar), which
can execute arbitrary code embedded in malicious serialized payloads.

REQUIREMENTS:
- Replace pickle with json for data that's just structured data (dicts/lists/strings)
- If the original use case genuinely requires arbitrary Python object serialization,
  note in why_fix_works that the data source must be cryptographically signed/trusted

EXAMPLE TRANSFORMATION:
  Before: obj = pickle.loads(data.encode())
  After:  import json
          obj = json.loads(data)
""" + OUTPUT_FORMAT_INSTRUCTIONS,

    "Weak JWT Implementation": """You are a senior security engineer fixing a JWT vulnerability.

VULNERABLE CODE:
{code}

CONTEXT: This code disables or bypasses JWT signature verification, meaning
any attacker can forge a valid-looking token.

REQUIREMENTS:
- Remove verify=False / {{"verify_signature": False}} entirely
- Explicitly specify allowed algorithms (e.g. algorithms=["HS256"]) -- never
  allow "none" as an algorithm
- Preserve the original variable names and surrounding logic

EXAMPLE TRANSFORMATION:
  Before: payload = jwt.decode(token, options={{"verify_signature": False}})
  After:  payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
""" + OUTPUT_FORMAT_INSTRUCTIONS,

    "Unvalidated Redirects": """You are a senior security engineer fixing an open redirect vulnerability.

VULNERABLE CODE:
{code}

CONTEXT: The redirect target comes directly from user input with no validation,
letting attackers craft links that redirect victims to malicious sites
(commonly used in phishing).

REQUIREMENTS:
- Validate the target against an allowlist of safe paths/domains before redirecting
- If only relative/internal paths should ever be valid, check the target starts with "/"
  and does not start with "//" (protocol-relative URL trick)

EXAMPLE TRANSFORMATION:
  Before: url = request.args.get('url')
          return redirect(url)
  After:  url = request.args.get('url', '/')
          if not url.startswith('/') or url.startswith('//'):
              url = '/'
          return redirect(url)
""" + OUTPUT_FORMAT_INSTRUCTIONS,

    "XSS Vulnerabilities": """You are a senior security engineer fixing a cross-site scripting (XSS) vulnerability.

VULNERABLE CODE:
{code}

CONTEXT: This code bypasses Jinja2's automatic HTML escaping (via |safe,
Markup(), or render_template_string with raw f-strings), letting attacker-
controlled input render as executable HTML/JS in the browser.

REQUIREMENTS:
- Remove the autoescape bypass; let Jinja2's default escaping handle output
- If raw HTML genuinely needs to be rendered, sanitize it first with a library
  like bleach before marking it safe

EXAMPLE TRANSFORMATION:
  Before: return Markup(f"<div>{{user_comment}}</div>")
  After:  return render_template("comment.html", user_comment=user_comment)
          # comment.html: <div>{{{{ user_comment }}}}</div>  (auto-escaped by Jinja2)
""" + OUTPUT_FORMAT_INSTRUCTIONS,
}


# Categories that don't get a code-fix template -- they get a static
# remediation guide instead (handled separately, see remediation_guides.py)
ARCHITECTURAL_CATEGORIES = {
    "Missing CSRF Protection",
    "Missing Security Headers",
    "Missing Rate Limiting",
    "Insecure Configuration",
}


def get_template(vuln_type: str) -> str | None:
    """Return the prompt template for a vuln_type, or None if not fixable via code-fix."""
    return TEMPLATES.get(vuln_type)


def is_fixable(vuln_type: str) -> bool:
    """Whether this category gets an LLM code fix vs a static remediation guide."""
    return vuln_type in TEMPLATES