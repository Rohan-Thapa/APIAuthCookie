using APIAuthCookie.Data;
using APIAuthCookie.Models;
using APIAuthCookie.Services;
using APIAuthCookie.DTOs;
using APIAuthCookie.Utilities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace APIAuthCookie.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly ITokenService _tokenService;
    private readonly AppDbContext _context;
    private readonly IConfiguration _config;

    public AuthController(
        ITokenService tokenService,
        AppDbContext context,
        IConfiguration config)
    {
        _tokenService = tokenService;
        _context = context;
        _config = config;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register(RegisterRequest request)
    {
        if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            return BadRequest("Username already exists");

        var user = new User
        {
            Username = request.Username,
            PasswordHash = PasswordHasher.HashPassword(request.Password)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return Ok(new { user.Id, user.Username });
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login(LoginRequest request)
    {
        var user = await _context.Users
            .Include(u => u.RefreshTokens)
            .FirstOrDefaultAsync(u => u.Username == request.Username);

        if (user == null || !PasswordHasher.VerifyPassword(request.Password, user.PasswordHash))
            return Unauthorized("Invalid credentials");

        var accessToken = _tokenService.GenerateAccessToken(user);
        var refreshToken = _tokenService.GenerateRefreshToken(
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown");

        refreshToken.UserId = user.Id;
        _context.RefreshTokens.Add(refreshToken);

        user.RefreshTokens.Add(refreshToken);
        await _context.SaveChangesAsync();

        SetRefreshTokenCookie(refreshToken.Token);

        return Ok(new { AccessToken = accessToken });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(refreshToken))
            return Unauthorized("No refresh token provided");

        var storedToken = await _context.RefreshTokens
            .Include(rt => rt.User)
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.IsActive);

        if (storedToken == null)
            return Unauthorized("Invalid or expired token");

        var newAccessToken = _tokenService.GenerateAccessToken(storedToken.User!);
        var newRefreshToken = _tokenService.GenerateRefreshToken(
            HttpContext.Connection.RemoteIpAddress?.ToString() ?? "Unknown");

        storedToken.Revoked = DateTime.UtcNow;
        storedToken.ReplacedByToken = newRefreshToken.Token;
        storedToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()!;

        newRefreshToken.UserId = storedToken.UserId;
        _context.RefreshTokens.Add(newRefreshToken);
        await _context.SaveChangesAsync();

        SetRefreshTokenCookie(newRefreshToken.Token);

        return Ok(new { AccessToken = newAccessToken });
    }

    [HttpPost("revoke-token")]
    public async Task<IActionResult> RevokeToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(refreshToken))
            return BadRequest("No refresh token provided");

        var storedToken = await _context.RefreshTokens
            .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.IsActive);

        if (storedToken == null)
            return BadRequest("Invalid token");

        storedToken.Revoked = DateTime.UtcNow;
        storedToken.RevokedByIp = HttpContext.Connection.RemoteIpAddress?.ToString()!;
        await _context.SaveChangesAsync();

        Response.Cookies.Delete("refreshToken");
        return Ok("Token revoked");
    }

    private void SetRefreshTokenCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(
                _config.GetValue<double>("Jwt:RefreshTokenExpirationDays")),
            Secure = true,
            SameSite = SameSiteMode.Strict
        };

        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }
}