# SecReview: a .NET secure code review sample

[![CI](https://github.com/MustiPat/secreview-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/MustiPat/secreview-dotnet/actions/workflows/ci.yml)

This repository shows how I run a secure code review and how I report it. It contains seven realistic vulnerabilities in a small .NET 8 library, a safe fix for each, and automated tests that prove both sides: the flaw is real, and the fix closes it.

Read [REVIEW.md](REVIEW.md) first. It is written the way a client report would be: severity, evidence, impact, and remediation for every finding.

## Layout

- `src/SecReview/Vulnerable.cs` has the insecure code, deliberately.
- `src/SecReview/Fixed.cs` has the remediated version of each method.
- `tests/SecReview.Tests/SecurityTests.cs` has an exploit test and a fix test per finding.

## Run

```bash
dotnet test tests/SecReview.Tests
```

## Scope

The examples cover injection, path traversal, broken access control, open redirect, weak password storage, timing leaks and cross-site scripting, which are the categories I see most often in line-of-business code. A real engagement also covers dependency scanning, secrets in history, configuration, authentication flows and infrastructure, as listed in the report's method section.

The vulnerable code is for demonstration only. Do not reuse it.
