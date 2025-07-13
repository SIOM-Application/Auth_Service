using System.Text;
using Auth_Service.Data;
using Auth_Service.Services;
using Auth_Service.Settings;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Auth_Service.Models;
using Microsoft.AspNetCore.Mvc;




var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddDbContext<AppDbContext>(Options =>
Options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
builder.Services.AddSingleton<TokenService>();

builder.Services.AddAuthentication("Bearer").AddJwtBearer("Bearer", options =>
{
    var jwt = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwt.Issuer,
        ValidAudience = jwt.Audience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Secret))
    };
});
builder.Services.AddAuthorization();
var app = builder.Build();

app.MapPost("/api/auth/register", async ([FromBody] RegisterRequest request, [FromServices] AppDbContext db) =>
{
    if (await db.Users.AnyAsync(u => u.Email == request.Email))
        return Results.BadRequest("Email Already Exists");

    var user = new User
    {
        Username = request.Username,
        Email = request.Email,
        PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
    };

    db.Users.Add(user);
    await db.SaveChangesAsync();
    return Results.Ok("Registered successfully");
});

// Make sure this is included at the top

app.MapPost("/api/auth/login", async ([FromBody] LoginRequest request, [FromServices] AppDbContext db, [FromServices] TokenService tokenService) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
    if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        return Results.Unauthorized();

    var token = tokenService.CreateToken(user);
    return Results.Ok(new { Token = token });
});

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.Run();

