# Secure code review report (sample)

Target: `SecReview` sample library, .NET 8. Review type: manual code review with exploit tests. Every finding below is reproduced by a test in `tests/SecReview.Tests`.

## Summary

| ID | Finding | CWE | Severity |
|----|---------|-----|----------|
| F1 | SQL injection through string concatenation | CWE-89 | Critical |
| F4 | Broken access control on invoices (IDOR) | CWE-639 | High |
| F6 | Passwords hashed with unsalted MD5 | CWE-327, CWE-759 | High |
| F2 | Path traversal in file resolution | CWE-22 | High |
| F7 | Reflected cross-site scripting in greeting | CWE-79 | Medium |
| F5 | Open redirect on return URL | CWE-601 | Medium |
| F3 | Timing leak in token comparison | CWE-208 | Low |

Severity reflects likely impact and ease of exploitation in a typical internet-facing business application.

## Findings

### F1. SQL injection (Critical)

`Vulnerable.BuildUserQuery` builds SQL by joining strings. Input such as `x' OR '1'='1` changes the meaning of the query and returns every row. Impact: data theft, modification, and in some databases command execution.
Fix: parameterised queries. The value is sent separately from the SQL text (`Fixed.BuildUserQuery`). With Entity Framework or Dapper this is the default; the risk appears wherever raw SQL is assembled.

### F4. Broken access control, IDOR (High)

`Vulnerable.GetInvoice` looks up a record by id only. Any signed-in user can read another customer's invoice by changing the number in the request.
Fix: authorise on the record, not just the session. The query must include the owner (`Fixed.GetInvoice`). Add the same check on update and delete paths.

### F6. Weak password storage (High)

`Vulnerable.HashPassword` uses unsalted MD5. Identical passwords give identical hashes, and a leaked table can be cracked at billions of guesses per second.
Fix: PBKDF2-SHA256 with a random salt and 600,000 iterations, verified in constant time (`Fixed.HashPassword`, `Fixed.VerifyPassword`). ASP.NET Core Identity or Argon2 are equally acceptable; the point is a salted, deliberately slow function. Existing users should be migrated at next login.

### F2. Path traversal (High)

`Vulnerable.ResolveFile` joins a user-supplied name onto a base folder. `../secret.txt` escapes it and can reach configuration files or other tenants' data.
Fix: resolve to a full path and require that it still starts with the base folder, returning nothing otherwise (`Fixed.ResolveFile`).

### F7. Cross-site scripting (Medium)

`Vulnerable.RenderGreeting` writes a display name into HTML unencoded. A name containing a script tag runs in other users' browsers.
Fix: encode on output (`Fixed.RenderGreeting`). Razor and Angular templates encode by default; the risk is raw HTML building, `Html.Raw` and `innerHTML`. Add a Content-Security-Policy header as defence in depth.

### F5. Open redirect (Medium)

`Vulnerable.RedirectTarget` sends users to any URL after login, which is useful for phishing because the link starts on the trusted domain.
Fix: accept only same-site relative paths and reject `//host` and `/\host` tricks (`Fixed.RedirectTarget`).

### F3. Timing leak in token comparison (Low)

`Vulnerable.TokensEqual` uses `==`, which stops at the first different character. With many measurements an attacker can recover a secret token a character at a time.
Fix: constant-time comparison (`Fixed.TokensEqual`).

## Method used on a real engagement

1. Threat model: entry points, trust boundaries, sensitive data.
2. Manual review of authentication, authorisation, input handling, data access, file handling, cryptography and error handling.
3. Automated scans for dependencies with known vulnerabilities, secrets in source and history, and static analysis.
4. Exploit proof for each finding, so nothing in the report is theoretical.
5. Prioritised fixes with code, then a re-test to confirm closure.

Reference frameworks: OWASP Top 10, OWASP ASVS, CWE.
