using System.Security.Cryptography;
using System.Text;
using AuthenticationCenter.Configuration;
using Microsoft.Extensions.Options;
namespace AuthenticationCenter.Helpers;

public class SecurityUsers
{
    private readonly JwtSetting _jwtSettings;

    public SecurityUsers(IOptions<JwtSetting> jwtSettings)
    {
        _jwtSettings = jwtSettings?.Value ?? throw new ArgumentNullException(nameof(jwtSettings));
    }
    
    public async Task<(string secretKey, string salt)> GenerateUserSecret(string userId, string userSalt)
    {
        // Derivar la clave secreta del usuario usando HMAC-SHA256 con salt
        string secretKey = await GenerateSecretKey(userId, userSalt);
        return (secretKey, userSalt);
    }
    
    private async Task<string> GenerateSecretKey(string userId, string salt)
    {
        using (var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(_jwtSettings.Secret)))
        {
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(userId + salt));
            return Convert.ToBase64String(hash);
        }
    }
}