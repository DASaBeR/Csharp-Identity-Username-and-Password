# 🧭 Project A — ASP.NET 8 Web API with Identity + JWT Authentication

> **Goal:** Build a small but complete Web API using ASP.NET Core 8, Entity Framework Core, and ASP.NET Identity for **Username & Password authentication** with **JWT tokens**.

This project is ideal for teaching **Identity**, **EF Core**, **JWT Authentication**, and **Authorization** step by step — perfect for beginners.

---

## 🧱 Step 0 — Create the Project

```bash
dotnet new webapi -n AuthDemo
cd AuthDemo
```

---

## 📦 Step 1 — Install Required Packages

Run these commands in your terminal:

```bash
dotnet add package Microsoft.AspNetCore.Identity.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.SqlServer
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package Microsoft.EntityFrameworkCore.Tools
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

### 📘 What Each Package Does

| Package | Purpose |
|----------|----------|
| `Microsoft.AspNetCore.Identity.EntityFrameworkCore` | Identity system built on EF Core |
| `Microsoft.EntityFrameworkCore.SqlServer` | SQL Server database provider |
| `Microsoft.EntityFrameworkCore.Design` / `Tools` | Enables `dotnet ef` migrations |
| `Microsoft.AspNetCore.Authentication.JwtBearer` | Validates JWT tokens in APIs |

👉 Optionally, install SQLite instead of SQL Server if you prefer a file-based DB:

```bash
dotnet add package Microsoft.EntityFrameworkCore.Sqlite
```

---

## ⚙️ Step 2 — Add ApplicationUser

Create a file: **`Models/ApplicationUser.cs`**

```csharp
using Microsoft.AspNetCore.Identity;

namespace AuthDemo.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? FullName { get; set; }
    }
}
```

> `IdentityUser` already includes: Id, UserName, Email, PasswordHash, etc.  
> You extend it for your app-specific fields.

---

## 🗃️ Step 3 — Create the Database Context

File: **`Data/AppDbContext.cs`**

```csharp
using AuthDemo.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthDemo.Data
{
    public class AppDbContext : IdentityDbContext<ApplicationUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options)
        {
        }
    }
}
```

---

## ⚡ Step 4 — Configure EF Core, Identity & JWT in Program.cs

Replace contents of **`Program.cs`** with:

```csharp
using System.Text;
using AuthDemo.Data;
using AuthDemo.Models;
using AuthDemo.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// 1️⃣ Database connection
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(connectionString));

// 2️⃣ Add Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequiredLength = 6;
    options.Password.RequireNonAlphanumeric = false;
})
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

// 3️⃣ Add JWT Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var key = Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]);
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(key)
    };
});

builder.Services.AddScoped<IJwtService, JwtService>();

builder.Services.AddControllers();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
```

---

## 🧩 Step 5 — Add Configuration (appsettings.json)

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=AuthDemoDb;Trusted_Connection=True;MultipleActiveResultSets=true"
  },
  "Jwt": {
    "Key": "super-secret-demo-key-change-me",
    "Issuer": "AuthDemo",
    "Audience": "AuthDemoClient",
    "ExpiryMinutes": "60"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

> ⚠️ Never commit real JWT keys or production connection strings to Git.  
> Use **User Secrets** or **Environment Variables**.

---

## 🧠 Step 6 — Create JWT Service

**`Services/IJwtService.cs`**

```csharp
using AuthDemo.Models;

public interface IJwtService
{
    string CreateToken(ApplicationUser user, IList<string> roles);
}
```

**`Services/JwtService.cs`**

```csharp
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthDemo.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

public class JwtService : IJwtService
{
    private readonly IConfiguration _config;
    public JwtService(IConfiguration config) => _config = config;

    public string CreateToken(ApplicationUser user, IList<string> roles)
    {
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id),
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new Claim("username", user.UserName ?? "")
        };

        claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expires = DateTime.UtcNow.AddMinutes(int.Parse(_config["Jwt:ExpiryMinutes"] ?? "60"));

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: expires,
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
```

---

## 🧾 Step 7 — DTOs for Register & Login

**`Models/RegisterDto.cs`**

```csharp
public class RegisterDto
{
    public string Username { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Password { get; set; } = null!;
}
```

**`Models/LoginDto.cs`**

```csharp
public class LoginDto
{
    public string Username { get; set; } = null!;
    public string Password { get; set; } = null!;
}
```

---

## 🔐 Step 8 — AuthController

**`Controllers/AuthController.cs`**

```csharp
using AuthDemo.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IJwtService _jwtService;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        IJwtService jwtService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _jwtService = jwtService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        var user = new ApplicationUser
        {
            UserName = dto.Username,
            Email = dto.Email
        };

        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded)
            return BadRequest(result.Errors.Select(e => e.Description));

        await _userManager.AddToRoleAsync(user, "User");
        return Ok(new { message = "User created successfully." });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        var user = await _userManager.FindByNameAsync(dto.Username);
        if (user == null) return Unauthorized();

        var result = await _signInManager.CheckPasswordSignInAsync(user, dto.Password, false);
        if (!result.Succeeded) return Unauthorized();

        var roles = await _userManager.GetRolesAsync(user);
        var token = _jwtService.CreateToken(user, roles);

        return Ok(new { token });
    }
}
```

---

## 🧱 Step 9 — Apply Migrations & Create Database

Run the following commands:

```bash
dotnet tool install --global dotnet-ef   # only once
dotnet ef migrations add InitialCreate
dotnet ef database update
```

✅ This creates all Identity tables (AspNetUsers, AspNetRoles, etc.)

---

## 🚀 Step 10 — Test Your Endpoints

Run the app:

```bash
dotnet run
```

Use **Swagger UI** or **Postman**.

### Register a new user:
```bash
POST /api/auth/register
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "P@ssw0rd1"
}
```

### Login:
```bash
POST /api/auth/login
{
  "username": "alice",
  "password": "P@ssw0rd1"
}
```

You’ll get back a token:
```json
{ "token": "eyJhbGciOi..." }
```

Copy this token and use it in headers:
```
Authorization: Bearer eyJhbGciOi...
```

---

## 🧩 Step 11 — Add a Protected Endpoint

**`Controllers/ValuesController.cs`**

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ValuesController : ControllerBase
{
    [HttpGet("public")]
    public IActionResult Public() => Ok("This is a public endpoint.");

    [Authorize]
    [HttpGet("private")]
    public IActionResult Private() => Ok("This is a private endpoint - valid JWT required.");

    [Authorize(Roles = "Admin")]
    [HttpGet("admin")]
    public IActionResult AdminOnly() => Ok("Admin only endpoint.");
}
```

---

## 🧠 Step 12 — Teaching Flow (Suggested for 10–15 min Episodes)

| Episode | Topic | Key Learning |
|----------|--------|--------------|
| 1 | Identity & EF Core Concepts | What Identity does, what EF Core is |
| 2 | Setup & Packages | Create project, add packages, explain each |
| 3 | ApplicationUser & DbContext | Explain inheritance & Identity tables |
| 4 | Configure Identity & JWT | Program.cs deep dive |
| 5 | Register/Login Endpoints | Walkthrough UserManager & SignInManager |
| 6 | Protect Endpoints & Test | Use JWT tokens, authorize attributes |

---

## 🛡️ Step 13 — Security & Best Practices

- Use **HTTPS** always.
- Store secrets in **User Secrets** or **Azure Key Vault**.
- Enforce strong password policies for production.
- Use refresh tokens for long sessions.
- Consider email confirmation and account lockout for better security.

---

## 🧩 Step 14 — Common Pitfalls

- Forgetting to call `UseAuthentication()` and `UseAuthorization()`.
- Wrong connection string or missing LocalDB.
- Missing EF Core Tools when running migrations.
- Using weak JWT secret keys.

---

## 🎉 Congratulations!

You now have a working **.NET 8 Web API** with:
- ASP.NET Core Identity  
- EF Core (SQL Server / SQLite)  
- JWT Authentication  
- Role-based Authorization  

Next episode: **Integrating Google Login** 🔗 and later **Web3 Login** using Ethereum signatures.

---

**Author:** Your Name  
**Course:** Identity, Authentication & Authorization in .NET 8 Web API  
**License:** MIT
