using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthFlowDoctor.Tests;

public class JwtHs256Tests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    public JwtHs256Tests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task IssueAndVerify_Succeeds()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        var issueReq = new
        {
            alg = "HS256",
            claims = new { sub = "u1", aud = "a1", iss = "i1", expMinutes = 5, nbfOffset = (int?)null },
            secret = "supersecretkey123",
            privateKeyPem = (string?)null,
            kid = (string?)null
        };
        var issueRes = await client.PostAsJsonAsync("/jwt/issue", issueReq);
        issueRes.EnsureSuccessStatusCode();
        var issued = await issueRes.Content.ReadFromJsonAsync<IssueJwtRes>();
        Assert.NotNull(issued);

        var verifyReq = new { token = issued!.Token, alg = "HS256", secretOrPublicKeyPem = "supersecretkey123", aud = (string?)null, iss = (string?)null, clockSkewSec = (int?)null };
        var verifyRes = await client.PostAsJsonAsync("/jwt/verify", verifyReq);
        verifyRes.EnsureSuccessStatusCode();
        var verified = await verifyRes.Content.ReadFromJsonAsync<VerifyJwtRes>();
        Assert.True(verified!.Valid);
    }

    [Fact]
    public async Task Expired_Fails()
    {
        var client = _factory.CreateClient();
        var issueReq = new { alg = "HS256", claims = new { sub = "u1", aud = "a1", iss = "i1", expMinutes = -1, nbfOffset = (int?)null }, secret = "supersecretkey123", privateKeyPem = (string?)null, kid = (string?)null };
        var issueRes = await client.PostAsJsonAsync("/jwt/issue", issueReq);
        var issued = await issueRes.Content.ReadFromJsonAsync<IssueJwtRes>();
        var verifyReq = new { token = issued!.Token, alg = "HS256", secretOrPublicKeyPem = "supersecretkey123", aud = (string?)null, iss = (string?)null, clockSkewSec = 0 };
        var verifyRes = await client.PostAsJsonAsync("/jwt/verify", verifyReq);
        var verified = await verifyRes.Content.ReadFromJsonAsync<VerifyJwtRes>();
        Assert.False(verified!.Valid);
    }

    [Fact]
    public async Task AudIssMismatch_Fails()
    {
        var client = _factory.CreateClient();
        var issueReq = new { alg = "HS256", claims = new { sub = "u1", aud = "a1", iss = "i1", expMinutes = 5, nbfOffset = (int?)null }, secret = "supersecretkey123", privateKeyPem = (string?)null, kid = (string?)null };
        var issueRes = await client.PostAsJsonAsync("/jwt/issue", issueReq);
        var issued = await issueRes.Content.ReadFromJsonAsync<IssueJwtRes>();
        var verifyReq = new { token = issued!.Token, alg = "HS256", secretOrPublicKeyPem = "supersecretkey123", aud = "wrong", iss = (string?)null, clockSkewSec = 0 };
        var verifyRes = await client.PostAsJsonAsync("/jwt/verify", verifyReq);
        var verified = await verifyRes.Content.ReadFromJsonAsync<VerifyJwtRes>();
        Assert.False(verified!.Valid);
    }
}

public class JwtRs256Tests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    public JwtRs256Tests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task IssueVerify_WithGeneratedKeyPair_Succeeds()
    {
        var client = _factory.CreateClient();
        var keys = await (await client.GetAsync("/jwt/keys/rs256")).Content.ReadFromJsonAsync<KeysRes>();
        Assert.NotNull(keys);
        var issueReq = new { alg = "RS256", claims = new { sub = "u1", aud = "a1", iss = "i1", expMinutes = 5, nbfOffset = (int?)null }, secret = (string?)null, privateKeyPem = keys!.PrivateKeyPem, kid = (string?)null };
        var issue = await (await client.PostAsJsonAsync("/jwt/issue", issueReq)).Content.ReadFromJsonAsync<IssueJwtRes>();
        var verifyReq = new { token = issue!.Token, alg = "RS256", secretOrPublicKeyPem = keys.PublicKeyPem, aud = (string?)null, iss = (string?)null, clockSkewSec = (int?)null };
        var verified = await (await client.PostAsJsonAsync("/jwt/verify", verifyReq)).Content.ReadFromJsonAsync<VerifyJwtRes>();
        Assert.True(verified!.Valid);
    }

    [Fact]
    public async Task Verify_WithDifferentPublicKey_FailsSignature()
    {
        var client = _factory.CreateClient();
        var keys1 = await (await client.GetAsync("/jwt/keys/rs256")).Content.ReadFromJsonAsync<KeysRes>();
        var keys2 = await (await client.GetAsync("/jwt/keys/rs256")).Content.ReadFromJsonAsync<KeysRes>();
        var issueReq = new { alg = "RS256", claims = new { sub = "u1", aud = "a1", iss = "i1", expMinutes = 5, nbfOffset = (int?)null }, secret = (string?)null, privateKeyPem = keys1!.PrivateKeyPem, kid = (string?)null };
        var issue = await (await client.PostAsJsonAsync("/jwt/issue", issueReq)).Content.ReadFromJsonAsync<IssueJwtRes>();
        var verifyReq = new { token = issue!.Token, alg = "RS256", secretOrPublicKeyPem = keys2!.PublicKeyPem, aud = (string?)null, iss = (string?)null, clockSkewSec = 0 };
        var verified = await (await client.PostAsJsonAsync("/jwt/verify", verifyReq)).Content.ReadFromJsonAsync<VerifyJwtRes>();
        Assert.False(verified!.Valid);
        Assert.Contains("signature invalid", verified.Reasons);
    }
}

public class CookieRoundtripTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    public CookieRoundtripTests(WebApplicationFactory<Program> factory) => _factory = factory;

    [Fact]
    public async Task SetThenCheck_ReturnsCookie()
    {
        var client = _factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, HandleCookies = true });
        var setReq = new { name = "roundtrip", value = "ok", domain = (string?)null, path = "/", sameSite = "Lax", secure = false, httpOnly = true, maxAgeSeconds = (int?)null };
        var setRes = await client.PostAsJsonAsync("/cookie/set", setReq);
        setRes.EnsureSuccessStatusCode();
        var check = await (await client.GetAsync("/cookie/check")).Content.ReadFromJsonAsync<Dictionary<string,string>>();
        Assert.True(check!.ContainsKey("roundtrip"));
        Assert.Equal("ok", check["roundtrip"]);
    }

    // Note: SameSite=None requires Secure; cross-site include behavior varies by browser and environment.
}

// Local DTO mirrors for test deserialization
public record IssueJwtRes(string Token, Dictionary<string, object?> Header, object Payload, DateTime ExpAt);
public record VerifyJwtRes(bool Valid, List<string> Reasons, Dictionary<string, object>? Claims);
public record KeysRes(string Alg, string PublicKeyPem, string PrivateKeyPem);