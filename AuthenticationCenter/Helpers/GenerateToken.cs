using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthenticationCenter.Configuration;
using AuthenticationCenter.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationCenter.Helpers;

public class GenerateToken
{
    private readonly JwtSetting _jwtSettings;

    public GenerateToken(IOptions<JwtSetting> jwtSettings)
    {
        _jwtSettings = jwtSettings?.Value ?? throw new ArgumentNullException(nameof(jwtSettings));
    }

    
    public async Task<AuthResult> GenerateJwt(string userId, string email, string security, string nonce, string userKey)
    {
        try
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            
            var key = Encoding.UTF8.GetBytes(userKey);
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                
                Subject = new ClaimsIdentity(new ClaimsIdentity(new Claim[]
                {
                    new Claim("Id", userId),
                    new Claim(JwtRegisteredClaimNames.Sub, email),
                    new Claim(JwtRegisteredClaimNames.Email, email),
                    new Claim(JwtRegisteredClaimNames.Jti, nonce),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.Now.ToUnixTimeSeconds().ToString()),
                    new Claim("Country", "Mexico"),
                    new Claim("Organization", "Authentication project"),
                })),
                Expires = DateTime.UtcNow.Add(_jwtSettings.ExpiryTime),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
                
            var jwtToken =  jwtTokenHandler.WriteToken(token);
            
            var refreshToken = new RefreshToken
            {
                JwtId = token.Id,
                Token = RandomGenerator.GenerateRandomString(32),
                AddedDate = DateTime.Now,
                ExpiryDate = DateTime.Now.AddMonths(1),
                IsRevoked = false,
                IsUsed = false,
                UserId = userId,

            };
            
            return new AuthResult
            {
                Token = jwtToken,
                RefreshToken = refreshToken,
                Result = true
            };
            
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex);
            throw;
        }
    }

    public async Task<TokenValidate> ValidateJwt(string token)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        
        try
        {
            // Seccion 1 formato JWT valido
            
            // 1. Validar que el token tenga tres partes (Header.Payload.Signature)
            if (string.IsNullOrWhiteSpace(token) || token.Split('.').Length != 3)
            {
                return new TokenValidate()
                {
                    Message = "Invalid format.",
                    Result = false
                };

            }
           var jwtTokenDesc = jwtTokenHandler.ReadJwtToken(token);
           
           
           var exp = jwtTokenDesc.Claims.Any(c => c.Type == JwtRegisteredClaimNames.Exp);
           var iat = jwtTokenDesc.Claims.Any(c => c.Type == JwtRegisteredClaimNames.Iat);
           if (!(exp && iat))
           {
               return new TokenValidate()
               {
                   Message = "Invalid date",
                   Result = false
               };
           }
           
           string IdUser = jwtTokenDesc.Claims.FirstOrDefault(c => c.Type == "Id")?.Value;
           
           return new TokenValidate()
           {
               Message = "Token Validate",
               Result = true,
               userId = IdUser
           };


        }
        catch (Exception ex)
        {

            return new TokenValidate()
            {
                Message = ex.Message,
                Result = false
            };
        }
    }

    public async Task<AuthResult> VerifyToken(string token, string UserKey)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        try
        {
            var key = Encoding.UTF8.GetBytes(UserKey);
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false, // Configura según tu dominio
                ValidateAudience = false, // Configura según tu audiencia
                ValidateLifetime = false, // Valida si el token está expirado
                ValidateIssuerSigningKey = true, // Verifica la firma del token
                IssuerSigningKey = new SymmetricSecurityKey(key),

                // Opcional: Si usas un emisor o audiencia específicos
                // ValidIssuer = "https://tudominio.com",
                // ValidAudience = "https://api.tudominio.com",
            };
            var tokenBeginVerified =
                jwtTokenHandler.ValidateToken(token, validationParameters, out SecurityToken validatedToken);

            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase);

                if (!result || tokenBeginVerified == null)
                {
                    return new AuthResult()
                    {
                        Result = false,
                        Message = "Token invalid."
                    };
                }
                    
            }

            var expClaim = tokenBeginVerified.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp);
            if (expClaim == null)
            {
                return new AuthResult()
                {
                    Result = false,
                    Message = "Token invalid."
                };
            }

            var utcExpiryDate = long.Parse(expClaim.Value);
            var expiryDate = DateTimeOffset.FromUnixTimeSeconds(utcExpiryDate).DateTime;

            if (expiryDate < DateTime.Now)
            {
                return new AuthResult()
                {
                    Result = true,
                    Message = "Token expired"
                };
            }

            return new AuthResult()
            {
                Result = true,
                Message = "Token valid",
      

            };

        }
        catch (Exception e)
        {
            return new AuthResult()
            {
                Result = false,
                Message = e.Message
            };
        }
    }
    
}