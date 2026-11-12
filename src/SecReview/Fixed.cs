using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace SecReview;

/// <summary>The remediated version of every method in Vulnerable.cs.</summary>
public static class Fixed
{
    // F1: parameterised query. The value travels separately from the SQL text.
    public static (string Sql, IReadOnlyDictionary<string, object> Parameters) BuildUserQuery(string name) =>
        ("SELECT Id, Name, Email FROM Users WHERE Name = @name",
         new Dictionary<string, object> { ["@name"] = name });

    // F2: resolve to a full path and require it to stay inside the base folder.
    public static string? ResolveFile(string baseDir, string userPath)
    {
        var root = Path.GetFullPath(baseDir).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var full = Path.GetFullPath(Path.Combine(root, userPath));
        return full.StartsWith(root, StringComparison.Ordinal) ? full : null;
    }

    // F3: constant-time comparison.
    public static bool TokensEqual(string supplied, string expected) =>
        CryptographicOperations.FixedTimeEquals(
            SHA256.HashData(Encoding.UTF8.GetBytes(supplied)),
            SHA256.HashData(Encoding.UTF8.GetBytes(expected)));

    // F4: the record must belong to the caller.
    public static Invoice? GetInvoice(string currentUser, int invoiceId, IReadOnlyList<Invoice> store) =>
        store.FirstOrDefault(i => i.Id == invoiceId && i.Owner == currentUser);

    // F5: only same-site relative paths. Rejects "//host", "/\host" and absolute URLs.
    public static string RedirectTarget(string returnUrl) =>
        returnUrl.Length > 0 && returnUrl[0] == '/'
        && (returnUrl.Length == 1 || (returnUrl[1] != '/' && returnUrl[1] != '\\'))
            ? returnUrl
            : "/";

    // F6: salted, slow key derivation (PBKDF2-SHA256) stored as iterations.salt.hash.
    private const int Iterations = 600_000;

    public static string HashPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, Iterations, HashAlgorithmName.SHA256, 32);
        return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    public static bool VerifyPassword(string password, string stored)
    {
        var parts = stored.Split('.');
        if (parts.Length != 3 || !int.TryParse(parts[0], out var iterations)) return false;
        var salt = Convert.FromBase64String(parts[1]);
        var expected = Convert.FromBase64String(parts[2]);
        var actual = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    // F7: encode on output.
    public static string RenderGreeting(string displayName) =>
        "<p>Welcome back, " + WebUtility.HtmlEncode(displayName) + "</p>";
}
