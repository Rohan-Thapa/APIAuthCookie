using APIAuthCookie.Models;

namespace APIAuthCookie.Services;

public interface ITokenService
{
    string GenerateAccessToken(User user);
    RefreshToken GenerateRefreshToken(string ipAddress);
}