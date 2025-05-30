﻿namespace APIAuthCookie.Models;

public class RefreshToken
{
    public int Id { get; set; }
    public string Token { get; set; } = string.Empty;
    public DateTime Expires { get; set; }
    public DateTime Created { get; set; }
    public string CreatedByIp { get; set; } = string.Empty;
    public DateTime? Revoked { get; set; }
    public string RevokedByIp { get; set; } = string.Empty;
    public string ReplacedByToken { get; set; } = string.Empty;

    public int UserId { get; set; }
    public User? User { get; set; }

    public bool IsExpired => DateTime.UtcNow >= Expires;
    public bool IsActive => Revoked == null && !IsExpired;
}