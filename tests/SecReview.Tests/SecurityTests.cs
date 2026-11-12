using SecReview;
using Xunit;

namespace SecReview.Tests;

// Each finding has two tests: one proves the flaw exists, one proves the fix closes it.
public class SecurityTests
{
    private static readonly string Base = Path.Combine(Path.GetTempPath(), "secreview", "public");

    private static readonly IReadOnlyList<Invoice> Store = new[]
    {
        new Invoice(1, "alice", 100m),
        new Invoice(2, "bob", 250m),
    };

    [Fact]
    public void F1_Vulnerable_SqlInjectionChangesTheQuery()
    {
        var sql = Vulnerable.BuildUserQuery("x' OR '1'='1");
        Assert.Contains("OR '1'='1'", sql);
    }

    [Fact]
    public void F1_Fixed_ValueStaysInAParameter()
    {
        var (sql, p) = Fixed.BuildUserQuery("x' OR '1'='1");
        Assert.DoesNotContain("OR", sql);
        Assert.Equal("x' OR '1'='1", p["@name"]);
    }

    [Fact]
    public void F2_Vulnerable_TraversalEscapesTheBaseFolder()
    {
        var path = Path.GetFullPath(Vulnerable.ResolveFile(Base, "../secret.txt"));
        Assert.False(path.StartsWith(Base + Path.DirectorySeparatorChar));
    }

    [Theory]
    [InlineData("../secret.txt")]
    [InlineData("a/../../secret.txt")]
    public void F2_Fixed_TraversalIsRejected(string input) =>
        Assert.Null(Fixed.ResolveFile(Base, input));

    [Fact]
    public void F2_Fixed_NormalFileIsAllowed() =>
        Assert.NotNull(Fixed.ResolveFile(Base, "docs/readme.txt"));

    [Fact]
    public void F3_Fixed_TokenComparisonStillCorrect()
    {
        Assert.True(Fixed.TokensEqual("abc123", "abc123"));
        Assert.False(Fixed.TokensEqual("abc124", "abc123"));
        Assert.False(Fixed.TokensEqual("", "abc123"));
    }

    [Fact]
    public void F4_Vulnerable_AnyUserCanReadAnyInvoice() =>
        Assert.NotNull(Vulnerable.GetInvoice("alice", 2, Store));

    [Fact]
    public void F4_Fixed_OnlyTheOwnerCanReadAnInvoice()
    {
        Assert.Null(Fixed.GetInvoice("alice", 2, Store));
        Assert.NotNull(Fixed.GetInvoice("bob", 2, Store));
    }

    [Fact]
    public void F5_Vulnerable_RedirectsAnywhere() =>
        Assert.Equal("https://evil.example", Vulnerable.RedirectTarget("https://evil.example"));

    [Theory]
    [InlineData("https://evil.example")]
    [InlineData("//evil.example")]
    [InlineData("/\\evil.example")]
    [InlineData("")]
    public void F5_Fixed_ExternalTargetsFallBackToHome(string url) =>
        Assert.Equal("/", Fixed.RedirectTarget(url));

    [Fact]
    public void F5_Fixed_LocalPathIsKept() =>
        Assert.Equal("/account/settings", Fixed.RedirectTarget("/account/settings"));

    [Fact]
    public void F6_Vulnerable_SamePasswordGivesSameHash() =>
        Assert.Equal(Vulnerable.HashPassword("hunter2"), Vulnerable.HashPassword("hunter2"));

    [Fact]
    public void F6_Fixed_SaltedAndVerifiable()
    {
        var a = Fixed.HashPassword("hunter2");
        var b = Fixed.HashPassword("hunter2");
        Assert.NotEqual(a, b);
        Assert.True(Fixed.VerifyPassword("hunter2", a));
        Assert.False(Fixed.VerifyPassword("hunter3", a));
        Assert.False(Fixed.VerifyPassword("hunter2", "garbage"));
    }

    [Fact]
    public void F7_Vulnerable_ScriptReachesTheOutput() =>
        Assert.Contains("<script>", Vulnerable.RenderGreeting("<script>alert(1)</script>"));

    [Fact]
    public void F7_Fixed_ScriptIsEncoded()
    {
        var html = Fixed.RenderGreeting("<script>alert(1)</script>");
        Assert.DoesNotContain("<script>", html);
        Assert.Contains("&lt;script&gt;", html);
    }
}
