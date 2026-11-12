using System.Security.Cryptography;
using System.Text;

namespace SecReview;

/// <summary>
/// Deliberately insecure code, written to resemble what turns up in real reviews.
/// Never copy this. Each method has a safe twin in Fixed.cs.
/// </summary>
public static class Vulnerable
{
    // F1 (CWE-89): user input concatenated into SQL.
    public static string BuildUserQuery(string name) =>
        "SELECT Id, Name, Email FROM Users WHERE Name = '" + name + "'";

    // F2 (CWE-22): path traversal. "..\..\secret.txt" escapes the base folder.
    public static string ResolveFile(string baseDir, string userPath) =>
        Path.Combine(baseDir, userPath);

    // F3 (CWE-208): ordinary comparison leaks timing information.
    public static bool TokensEqual(string supplied, string expected) =>
        supplied == expected;

    // F4 (CWE-639): insecure direct object reference, no ownership check.
    public static Invoice? GetInvoice(string currentUser, int invoiceId, IReadOnlyList<Invoice> store) =>
        store.FirstOrDefault(i => i.Id == invoiceId);

    // F5 (CWE-601): open redirect, any URL accepted.
    public static string RedirectTarget(string returnUrl) => returnUrl;

    // F6 (CWE-327/759): fast, unsalted hash for passwords.
    public static string HashPassword(string password) =>
        Convert.ToHexString(MD5.HashData(Encoding.UTF8.GetBytes(password)));

    // F7 (CWE-79): user input written into HTML without encoding.
    public static string RenderGreeting(string displayName) =>
        "<p>Welcome back, " + displayName + "</p>";
}

public record Invoice(int Id, string Owner, decimal Amount);
