﻿namespace APIAuthCookie.Models;

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public List<RefreshToken> RefreshTokens { get; set; } = new();
}