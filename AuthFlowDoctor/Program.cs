using System.Security.Cryptography;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateSlimBuilder(args);

builder.Services.AddCors(options =>
{
    options.AddPolicy("Local", policy =>
    {
        policy.WithOrigins(
                "http://localhost:5173",
                "http://localhost:3000",
                "http://127.0.0.1:5173",
                "http://127.0.0.1:3000"
            )
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials();
    });
});

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.SerializerOptions.TypeInfoResolverChain.Insert(0, AppJsonSerializerContext.Default);
});

var app = builder.Build();

// Global JSON error handler
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.ContentType = "application/json";
        var error = context.Features.Get<Microsoft.AspNetCore.Diagnostics.IExceptionHandlerFeature>()?.Error;
        if (error is TaskCanceledException or OperationCanceledException)
        {
            context.Response.StatusCode = StatusCodes.Status504GatewayTimeout;
            await context.Response.WriteAsJsonAsync(new { error = "request canceled or timed out" });
            return;
        }
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsJsonAsync(new { error = "internal error" });
    });
});

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseCors("Local");

// JWT endpoints
app.MapPost("/jwt/issue", (IssueJwtReq request) =>
{
    var now = DateTimeOffset.UtcNow;
    var exp = now.AddMinutes(request.Claims.ExpMinutes);
    var nbf = request.Claims.NbfOffset.HasValue ? now.AddSeconds(request.Claims.NbfOffset.Value) : (DateTimeOffset?)null;

    var claims = new List<System.Security.Claims.Claim>
    {
        new(JwtRegisteredClaimNames.Sub, request.Claims.Sub ?? string.Empty)
    };

    var handler = new JwtSecurityTokenHandler();
    SecurityKey key;
    SigningCredentials creds;
    var header = new Dictionary<string, object?>();

    if (string.Equals(request.Alg, "HS256", StringComparison.OrdinalIgnoreCase))
    {
        var secret = string.IsNullOrEmpty(request.Secret) ? JwtUtil.DefaultHs256Secret : request.Secret!;
        var headerObj = new Dictionary<string, object?> { { "alg", "HS256" }, { "typ", "JWT" } };
        var payloadObj = new Dictionary<string, object?>();
        if (!string.IsNullOrEmpty(request.Claims.Sub)) payloadObj["sub"] = request.Claims.Sub;
        if (!string.IsNullOrEmpty(request.Claims.Aud)) payloadObj["aud"] = request.Claims.Aud;
        if (!string.IsNullOrEmpty(request.Claims.Iss)) payloadObj["iss"] = request.Claims.Iss;
        payloadObj["exp"] = exp.ToUnixTimeSeconds();
        if (nbf.HasValue) payloadObj["nbf"] = nbf.Value.ToUnixTimeSeconds();
        var headerB64 = JwtUtil.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(headerObj));
        var payloadB64 = JwtUtil.Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payloadObj));
        var signingInput = Encoding.ASCII.GetBytes($"{headerB64}.{payloadB64}");
        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
        var sig = JwtUtil.Base64UrlEncode(hmac.ComputeHash(signingInput));
        var jwtToken = $"{headerB64}.{payloadB64}.{sig}";
        return Results.Ok(new IssueJwtRes(jwtToken, headerObj, new
        {
            sub = request.Claims.Sub,
            aud = request.Claims.Aud,
            iss = request.Claims.Iss,
            expMinutes = request.Claims.ExpMinutes,
            nbfOffset = request.Claims.NbfOffset
        }, exp.UtcDateTime));
    }
    else if (string.Equals(request.Alg, "RS256", StringComparison.OrdinalIgnoreCase))
    {
        if (string.IsNullOrWhiteSpace(request.PrivateKeyPem))
        {
            throw new ArgumentException("privateKeyPem required for RS256");
        }
        using var rsa = RSA.Create();
        JwtUtil.ImportPkcs8PrivateKeyFromPem(rsa, request.PrivateKeyPem!);
        key = new RsaSecurityKey(rsa);
        if (!string.IsNullOrWhiteSpace(request.Kid))
        {
            ((RsaSecurityKey)key).KeyId = request.Kid;
            header["kid"] = request.Kid;
        }
        creds = new SigningCredentials(key, SecurityAlgorithms.RsaSha256);
        header["alg"] = "RS256";
    }
    else
    {
        throw new ArgumentException("Unsupported alg");
    }

    var token = new JwtSecurityToken(
        claims: claims,
        notBefore: nbf?.UtcDateTime,
        expires: exp.UtcDateTime,
        signingCredentials: creds
    );
    var tokenString = handler.WriteToken(token);
    
    var payload = new
    {
        sub = request.Claims.Sub,
        aud = request.Claims.Aud,
        iss = request.Claims.Iss,
        expMinutes = request.Claims.ExpMinutes,
        nbfOffset = request.Claims.NbfOffset
    };
    
    return Results.Ok(new IssueJwtRes(tokenString, header, payload, exp.UtcDateTime));
});

app.MapPost("/jwt/verify", (VerifyJwtReq request) =>
{
    var reasons = new List<string>();
    var valid = false;
    Dictionary<string, object>? claimsOut = null;

    try
    {
        var parts = request.Token.Split('.');
        if (parts.Length != 3) throw new ArgumentException("token format");
        var headerJson = Encoding.UTF8.GetString(JwtUtil.Base64UrlDecode(parts[0]));
        var payloadJson = Encoding.UTF8.GetString(JwtUtil.Base64UrlDecode(parts[1]));
        var sigBytes = JwtUtil.Base64UrlDecode(parts[2]);
        var signingInput = Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]);

        if (string.Equals(request.Alg, "HS256", StringComparison.OrdinalIgnoreCase))
        {
            var secret = string.IsNullOrEmpty(request.SecretOrPublicKeyPem) ? JwtUtil.DefaultHs256Secret : request.SecretOrPublicKeyPem!;
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(secret));
            var expected = hmac.ComputeHash(signingInput);
            if (!expected.SequenceEqual(sigBytes)) reasons.Add("signature invalid");
        }
        else if (string.Equals(request.Alg, "RS256", StringComparison.OrdinalIgnoreCase))
        {
            if (string.IsNullOrWhiteSpace(request.SecretOrPublicKeyPem)) throw new ArgumentException("public key PEM required");
            using var rsa = RSA.Create();
            JwtUtil.ImportSpkiPublicKeyFromPem(rsa, request.SecretOrPublicKeyPem!);
            if (!rsa.VerifyData(signingInput, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)) reasons.Add("signature invalid");
        }
        else throw new ArgumentException("Unsupported alg");

        var payload = JsonSerializer.Deserialize<Dictionary<string, object>>(payloadJson) ?? new();
        claimsOut = payload;

        var now = DateTimeOffset.UtcNow;
        var skew = TimeSpan.FromSeconds(request.ClockSkewSec ?? 120);
        if (payload.TryGetValue("exp", out var expVal) && long.TryParse(expVal.ToString(), out var expSec))
        {
            if (now > DateTimeOffset.FromUnixTimeSeconds(expSec) + skew) reasons.Add("expired");
        }
        if (payload.TryGetValue("nbf", out var nbfVal) && long.TryParse(nbfVal.ToString(), out var nbfSec))
        {
            if (now < DateTimeOffset.FromUnixTimeSeconds(nbfSec) - skew) reasons.Add("nbf not reached");
        }
        if (!string.IsNullOrEmpty(request.Aud) && (!payload.TryGetValue("aud", out var audVal) || audVal?.ToString() != request.Aud))
        {
            reasons.Add("aud mismatch");
        }
        if (!string.IsNullOrEmpty(request.Iss) && (!payload.TryGetValue("iss", out var issVal) || issVal?.ToString() != request.Iss))
        {
            reasons.Add("iss mismatch");
        }

        valid = reasons.Count == 0;
    }
    catch (Exception)
    {
        reasons.Add("invalid token");
    }

    return Results.Ok(new VerifyJwtRes(valid, reasons, claimsOut));
});

app.MapGet("/jwt/keys/rs256", () =>
{
    using var rsa = RSA.Create(2048);
    var privatePem = JwtUtil.ExportPkcs8PrivateKeyPem(rsa);
    var publicPem = JwtUtil.ExportSpkiPublicKeyPem(rsa);
    return Results.Ok(new { alg = "RS256", publicKeyPem = publicPem, privateKeyPem = privatePem });
});

// Cookie endpoints
app.MapPost("/cookie/set", (HttpContext ctx, SetCookieReq req) =>
{
    var options = new CookieOptions
    {
        HttpOnly = req.HttpOnly,
        Secure = req.Secure,
        SameSite = req.SameSite switch
        {
            "Strict" => SameSiteMode.Strict,
            "None" => SameSiteMode.None,
            _ => SameSiteMode.Lax
        },
        Domain = string.IsNullOrWhiteSpace(req.Domain) ? null : req.Domain,
        Path = string.IsNullOrWhiteSpace(req.Path) ? "/" : req.Path,
    };
    if (req.MaxAgeSeconds.HasValue)
    {
        options.MaxAge = TimeSpan.FromSeconds(req.MaxAgeSeconds.Value);
    }
    ctx.Response.Cookies.Append(req.Name, req.Value ?? string.Empty, options);
    // Mirror back details
    return Results.Ok(new
    {
        name = req.Name,
        value = req.Value,
        domain = options.Domain,
        path = options.Path,
        sameSite = options.SameSite.ToString(),
        secure = options.Secure,
        httpOnly = options.HttpOnly,
        maxAge = options.MaxAge?.TotalSeconds
    });
});

app.MapGet("/cookie/check", (HttpContext ctx) =>
{
    var dict = ctx.Request.Cookies.ToDictionary(kv => kv.Key, kv => kv.Value);
    return Results.Ok(dict);
});

app.MapGet("/cookie/clear", (HttpContext ctx, string name, string? domain, string? path) =>
{
    var options = new CookieOptions
    {
        Domain = string.IsNullOrWhiteSpace(domain) ? null : domain,
        Path = string.IsNullOrWhiteSpace(path) ? "/" : path,
        Expires = DateTimeOffset.UtcNow.AddDays(-1)
    };
    ctx.Response.Cookies.Append(name, string.Empty, options);
    return Results.Ok(new { cleared = name, domain = options.Domain, path = options.Path });
});

// Echo headers
app.MapGet("/echo/headers", (HttpContext ctx) =>
{
    var headers = ctx.Request.Headers.ToDictionary(h => h.Key, h => h.Value.ToString());
    var cookies = ctx.Request.Cookies.ToDictionary(kv => kv.Key, kv => kv.Value);
    return Results.Ok(new EchoRes(headers, cookies));
});

// Meta
app.MapGet("/healthz", () => Results.Ok(new { status = "ok", time = DateTimeOffset.UtcNow }));
app.MapGet("/version", () => Results.Ok(new { name = "AuthFlowDoctor", version = "0.1.0" }));

app.Run();

// Models
public sealed record IssueJwtReq(string Alg, IssueJwtClaims Claims, string? Secret, string? PrivateKeyPem, string? Kid);
public sealed record IssueJwtClaims(string? Sub, string? Aud, string? Iss, int ExpMinutes, int? NbfOffset);
public sealed record IssueJwtRes(string Token, Dictionary<string, object?> Header, object Payload, DateTime ExpAt);

public sealed record VerifyJwtReq(string Token, string Alg, string? SecretOrPublicKeyPem, string? Aud, string? Iss, int? ClockSkewSec);
public sealed record VerifyJwtRes(bool Valid, List<string> Reasons, Dictionary<string, object>? Claims);

public sealed record SetCookieReq(string Name, string? Value, string? Domain, string? Path, string SameSite, bool Secure, bool HttpOnly, int? MaxAgeSeconds);
public sealed record EchoRes(Dictionary<string, string> Headers, Dictionary<string, string> Cookies);

// Utilities
static class JwtUtil
{
    public const string DefaultHs256Secret = "demo-hs256-secret";

    public static void ImportPkcs8PrivateKeyFromPem(RSA rsa, string pem)
    {
        var keyData = ReadPem("PRIVATE KEY", pem);
        rsa.ImportPkcs8PrivateKey(keyData, out _);
    }

    public static void ImportSpkiPublicKeyFromPem(RSA rsa, string pem)
    {
        var keyData = ReadPem("PUBLIC KEY", pem);
        rsa.ImportSubjectPublicKeyInfo(keyData, out _);
    }

    public static string ExportPkcs8PrivateKeyPem(RSA rsa)
    {
        var bytes = rsa.ExportPkcs8PrivateKey();
        return WritePem("PRIVATE KEY", bytes);
    }

    public static string ExportSpkiPublicKeyPem(RSA rsa)
    {
        var bytes = rsa.ExportSubjectPublicKeyInfo();
        return WritePem("PUBLIC KEY", bytes);
    }

    private static byte[] ReadPem(string label, string pem)
    {
        var header = $"-----BEGIN {label}-----";
        var footer = $"-----END {label}-----";
        var start = pem.IndexOf(header, StringComparison.Ordinal);
        var end = pem.IndexOf(footer, StringComparison.Ordinal);
        if (start < 0 || end < 0) throw new ArgumentException($"Invalid PEM: {label}");
        var base64 = pem.Substring(start + header.Length, end - (start + header.Length)).Replace("\r", string.Empty).Replace("\n", string.Empty).Trim();
        return Convert.FromBase64String(base64);
    }

    private static string WritePem(string label, byte[] der)
    {
        var base64 = Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks);
        var sb = new StringBuilder();
        sb.AppendLine($"-----BEGIN {label}-----");
        sb.AppendLine(base64);
        sb.AppendLine($"-----END {label}-----");
        return sb.ToString();
    }

    public static string Base64UrlEncode(byte[] data)
    {
        return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public static byte[] Base64UrlDecode(string input)
    {
        string padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}

[JsonSerializable(typeof(IssueJwtReq))]
[JsonSerializable(typeof(IssueJwtClaims))]
[JsonSerializable(typeof(IssueJwtRes))]
[JsonSerializable(typeof(VerifyJwtReq))]
[JsonSerializable(typeof(VerifyJwtRes))]
[JsonSerializable(typeof(SetCookieReq))]
[JsonSerializable(typeof(EchoRes))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{
}

// Expose Program for WebApplicationFactory in tests
public partial class Program { }
