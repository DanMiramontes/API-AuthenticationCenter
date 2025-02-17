using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using AuthenticationCenter.Configuration;
using AuthenticationCenter.Dtos;
using AuthenticationCenter.Helpers;
using AuthenticationCenter.Interfaces;
using AuthenticationCenter.Models;
using AuthenticationCenter.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationCenter.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IRegisterRepository _registerRepository;
    private readonly ILoginRepository _loginRepository;
    private readonly GenerateToken _generateToken;
    private readonly EmailService _emailService;
    private readonly SecurityUsers _securityUsers;
    private readonly IRefreshToken _refreshToken;

    
    public AuthenticationController(IRegisterRepository registerRepository,ILoginRepository loginRepository, IRefreshToken refreshToken, GenerateToken generateToken, EmailService emailService, SecurityUsers securityUsers)
    {
        _registerRepository = registerRepository;
        _loginRepository = loginRepository;
        _refreshToken = refreshToken;
        _generateToken = generateToken;
        _emailService = emailService;
        _securityUsers = securityUsers;
    }
    
    [HttpPost("Register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto request)
    {
        if (string.IsNullOrEmpty(request.EmailAddress) || string.IsNullOrEmpty(request.Password))
        {
            return Unauthorized(new { Message = "Credentials are required." });
        }
        
        bool email = await _registerRepository.GetEmailRegister(request.EmailAddress);
        if (email)
        {
            return BadRequest(new { Message = "Registration email already exists." });
        }
        
        
        var passwrod = PasswordHelper.HashPassword(request.Password);
        Guid securityStamp = Guid.NewGuid();
        Guid concurrencyStamp = Guid.NewGuid();
        
        byte[] tokenBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(tokenBytes);
        }
        string verificationToken = Convert.ToBase64String(tokenBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        
        // Generar hash del token
        using var sha256 = SHA256.Create();
        byte[] tokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(verificationToken));
        string tokenHashString = Convert.ToBase64String(tokenHash);

        
        Guid userID = await _registerRepository.InsertUser(request.Name, request.EmailAddress, passwrod.Hash,passwrod.salt, securityStamp, concurrencyStamp,tokenHashString);

        if (userID == Guid.Empty)
        {
            return BadRequest(new { Message = "Invalid credentials." });
        }
        
        // Generar la URL de confirmación
        var encodedUserId = Convert.ToBase64String(Encoding.UTF8.GetBytes(userID.ToString()));
        var callbackUrl =
            $"{Request.Scheme}://{Request.Host}/api/Authentication/ConfirmEmail?userId={encodedUserId}&token={verificationToken}";
        
        // Crear el cuerpo del correo electrónico
        var emailBody = 
            $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>";
        
        await _emailService.SendEmail(request.EmailAddress, "Confirm your email", emailBody);
        
        return Ok(new { Message = "User created successfully. Please verify your email." });
    }
    [HttpGet("ConfirmEmail")]
    public async Task<IActionResult> ConfirmEmail([FromQuery] string userId, [FromQuery] string token)
    {
        Guid decodeUserId = Guid.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(userId)));
        //Calcular el hash del token recibido
        using var sha256 = SHA256.Create();
        byte[] tokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        string tokenHashString = Convert.ToBase64String(tokenHash);
        
        
        if (decodeUserId == Guid.Empty || tokenHashString == string.Empty)
        {
            return Unauthorized(new { Message = "Invalid credentials." });
        }
        string emailUser = await _registerRepository.EmailRegister(decodeUserId);
        if (emailUser == string.Empty)
        {
            return BadRequest(new { Message = "Invalid credentials." });
        }
        var userStatus = await _registerRepository.GetLockoutEnd(decodeUserId);
        if (userStatus > DateTime.Now)
        {
            return BadRequest(new { Message = "Your account is temporarily locked due to multiple failed attempts. Please try again later." });
        }
        
        int validTokenCount = await _registerRepository.GetEmailVerifications(decodeUserId, tokenHashString,DateTime.Now);

        if (validTokenCount == 0)
        {
            // Incrementar el contador de intentos fallidos
            bool incrementFailures = await _registerRepository.IncrementFailures(decodeUserId);
            
            // Verificar si se debe bloquear al usuario
            int failureCount = await _registerRepository.GetFailuresCount(decodeUserId);

            if (failureCount >= 5)
            {
                bool lockUser = await _registerRepository.LockUser(decodeUserId, DateTime.Now);
            }
            return BadRequest(new { Message = "Invalid token or token expired." });
        }
        // Si el token es válido, confirmar el correo
        bool confirmEmail =  await _registerRepository.ConfirmEmail(decodeUserId);

        if (confirmEmail)
        {
            // Eliminar el token después de su uso
            bool deleteTokenQuery =  await _registerRepository.DeleteTokenEmail(decodeUserId,tokenHashString);
        }
        return Ok(new { Message = "Email confirmed successfully." });
    }
    [HttpPost("ResentConfirmation")]
    public async Task<IActionResult> ResentConfirmation([FromQuery] string userId, [FromQuery] string token)
    {
        Guid decodeUserId = Guid.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(userId)));
        
        using var sha256 = SHA256.Create();
        byte[] tokenHash = sha256.ComputeHash(Encoding.UTF8.GetBytes(token));
        string tokenHashString = Convert.ToBase64String(tokenHash);
        if (decodeUserId == Guid.Empty || tokenHashString == string.Empty)
        {
            return Unauthorized(new { Message = "Invalid credentials." });
        }
        string emailUser = await _registerRepository.EmailRegister(decodeUserId);
        if (emailUser == string.Empty)
        {
            return BadRequest(new { Message = "Invalid credentials." });
        }

        var userStatus = await _registerRepository.GetLockoutEnd(decodeUserId);
        if (userStatus > DateTime.Now)
        {
            
            // Verificar si se debe bloquear al usuario
            int failureCount = await _registerRepository.GetFailuresCount(decodeUserId);

            if (failureCount >= 5)
            {
                return BadRequest(new { Message = "Your account is temporarily locked due to multiple failed attempts. Please try again later." });
            }
            
        }
        
        bool validTokenCount = await _registerRepository.DeleteTokenEmail(decodeUserId, tokenHashString);

        if (!validTokenCount)
        {
            return NotFound(new { Message = "Invalid credentials." });
        }
        
        byte[] tokenBytes = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(tokenBytes);
        }
        string verificationToken = Convert.ToBase64String(tokenBytes).Replace("+", "-").Replace("/", "_").TrimEnd('=');
        
        // Generar hash del token
        using var sha256R = SHA256.Create();
        byte[] tokenHashR = sha256R.ComputeHash(Encoding.UTF8.GetBytes(verificationToken));
        string tokenHashStringR = Convert.ToBase64String(tokenHashR);
        
        bool insterNewEmail = await _registerRepository.InsertEmailVerification(decodeUserId, tokenHashStringR);
        
        if (!insterNewEmail)
        {
            return NotFound(new { Message = "Invalid credentials." });
        }
        
        // Generar la URL de confirmación
        var encodedUserId = Convert.ToBase64String(Encoding.UTF8.GetBytes(decodeUserId.ToString()));
        var callbackUrl =
            $"{Request.Scheme}://{Request.Host}/api/Authentication/ConfirmEmail?userId={encodedUserId}&token={verificationToken}";
        
        // Crear el cuerpo del correo electrónico
        var emailBody = 
            $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>";
        
        await _emailService.SendEmail(emailUser, "Confirm your email", emailBody);
        
        return Ok(new { Message = "Resent Confirmation. Please verify your email." });
    }
     [HttpPost("Login")]
    public async Task<IActionResult> Login([FromBody] LoginDto request)
    {
        if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
        {
            return Unauthorized(new { Message = "Credentials are required." });
        }

        User userRegister = await _loginRepository.GetUserRegister(request.Email);
            
        if (string.IsNullOrEmpty(userRegister.Id.ToString()) || string.IsNullOrEmpty(userRegister.PasswordHash))
        {
            return Unauthorized(new { Message = "Invalid Credentials." });
        }
        
        // Verificar si la cuenta está bloqueada
        if (userRegister.LockoutEnd.HasValue && userRegister.LockoutEnd.Value > DateTime.Now)
        {
            return Unauthorized(new { Message = "Your account is locked. Please try again later." });
        }
        
        // Verificar si el correo está confirmado
        if (!userRegister.EmailConfirmed)
        {
            return Unauthorized(new { Message = "Please confirm your email before logging in." });
        }
        
        var passwordVerificationResult = PasswordHelper.VerifyPassword(request.Password,userRegister.PasswordHash,userRegister.SaltHash);
        if (!passwordVerificationResult)
        {
            // Incrementar el contador de intentos fallidos
            bool incrementFailures = await _registerRepository.IncrementFailures(userRegister.Id);
            
            // Verificar si se debe bloquear al usuario
            int failureCount = await _registerRepository.GetFailuresCount(userRegister.Id);

            if (failureCount >= 5)
            {
                bool lockUser = await _registerRepository.LockUser(userRegister.Id, DateTime.Now);
            }
            return BadRequest(new { Message = "Invalid credentials." });
        }
        
        // Comprobar si el usuario ya tiene un nonce activo
        string existingNonce = await _loginRepository.CheckExistingNonceQuery(userRegister.Id, DateTime.Now);
        // Si ya existe un nonce, eliminarlo o invalidarlo
        if (string.IsNullOrEmpty(existingNonce))
        {
            bool invalidateNonceQuery = await _loginRepository.InvalidateNonceQuery(userRegister.Id);
        }
        // Generar un Nonce unico
        string newNonce = Guid.NewGuid().ToString();
        bool setNewNonce = await _loginRepository.SetNonce(userRegister.Id,newNonce, DateTime.Now);
        if (!setNewNonce)
        {
            return NotFound(new { Message = "Invalid credentials." });
        }
        
        //validar que se tenga key
        
        if (string.IsNullOrEmpty(userRegister.UserKey))
        {
            // Generar nuevo key token
            (string secretKey, string salt) keyUser = await _securityUsers.GenerateUserSecret(userRegister.Id.ToString(), userRegister.SaltHash );

            if (string.IsNullOrEmpty(keyUser.secretKey))
            {
                return NotFound(new { Message = "Invalid credentials." });
            }
            //Almacenar el nuevo keyUser
            bool setKey = await _loginRepository.SetKeyUserRegister(userRegister.Id, keyUser.secretKey);
        
            if (!setKey)
            {
                return NotFound(new { Message = "Invalid credentials." });
            } 
           
        }
        string userKey = await _loginRepository.GetKeyser(userRegister.Id);
        
        var result = await _generateToken.GenerateJwt(userRegister.Id.ToString(),userRegister.Email,userRegister.SecurityStamp, newNonce,userKey);
        RefreshToken refreshToken = result.RefreshToken;
        bool insertRefreshTokenQuery = await _loginRepository.InsertRefreshToken(
           refreshToken.UserId, refreshToken.Token, refreshToken.JwtId, refreshToken.IsUsed, refreshToken.IsRevoked,refreshToken.AddedDate,refreshToken.ExpiryDate );
        
        Response.Cookies.Append("auth_token", result.Token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        });
        
        return Ok(new
        {
            Message = "Login successful.",
            Token = result.Token,
            RefreshToken = refreshToken,
        });
    }
    
    [HttpPost("RefreshToken")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenRequest request)
    {
        if (string.IsNullOrEmpty(request.Token) || string.IsNullOrEmpty(request.RefreshToken))
        {
            return Unauthorized(new { Message = "Invalid credentials."  });
        }
        
        TokenValidate result = await _generateToken.ValidateJwt(request.Token);

        User user = await _refreshToken.GetUserRegister(Guid.Parse(result.userId));

        if (string.IsNullOrEmpty(user?.Id.ToString()))
        {
            return Unauthorized(new { Message = "Invalid Token." });
        }
        var jwt = await _generateToken.VerifyToken(request.Token, user.UserKey);

        if (jwt.Result == false)
        {
            return Unauthorized(new { Message = jwt.Message });
        }
        TokenQuery jwtRefreshToken = await _refreshToken.GetRefreshToken(request.RefreshToken);
        
        if (jwtRefreshToken.IsUsed || jwtRefreshToken.IsRevoked)
        {
            return Unauthorized(new { Message = "Invalid Token." });
        }
        
        if(jwtRefreshToken == null)
        {
            return Unauthorized(new { Message = "Invalid Token." });
        }

        if (user.Id != jwtRefreshToken.UserId)
        {
            return Unauthorized(new { Message = "Invalid Token." });
        }
        if (jwtRefreshToken.IsUsed || jwtRefreshToken.IsRevoked)
        {
            return Unauthorized(new { Message = "Invalid Token." });
        }
        /*
       if (result.claim.Jti != jwtRefreshToken.JwtId)
        {
            // Revokar token 
            return Unauthorized(new { Message = "Invalid Token." });
        }
        */

        if (jwtRefreshToken.ExpiryDate < DateTime.Now)
        {
            return BadRequest(new { Message = "Token expired." });
        }
        
        // actualizar token Isused 
        bool updateToken = await _refreshToken.SetStatusToken(jwtRefreshToken.UserId, jwtRefreshToken.Token);
        
        // Comprobar si el usuario ya tiene un nonce activo
        string existingNonce = await _loginRepository.CheckExistingNonceQuery(user.Id, DateTime.Now);
        // Si ya existe un nonce, eliminarlo o invalidarlo
        if (string.IsNullOrEmpty(existingNonce))
        {
            bool invalidateNonceQuery = await _loginRepository.InvalidateNonceQuery(user.Id);
        }
        // Generar un Nonce unico
        string newNonce = Guid.NewGuid().ToString();
        bool setNewNonce = await _loginRepository.SetNonce(user.Id,newNonce, DateTime.Now);
        if (!setNewNonce)
        {
            return NotFound(new { Message = "Invalid credentials." });
        }
        // Generar nuevo jwt y refresh 
        var resultRefreshToken = await _generateToken.GenerateJwt(user.Id.ToString(),user.Email,user.SecurityStamp, newNonce,user.UserKey);
        // Cargar nuevo token 
        RefreshToken refreshToken = resultRefreshToken.RefreshToken;
        bool insertRefreshTokenQuery = await _loginRepository.InsertRefreshToken(
            refreshToken.UserId, refreshToken.Token, refreshToken.JwtId, refreshToken.IsUsed, refreshToken.IsRevoked,refreshToken.AddedDate,refreshToken.ExpiryDate );

                
        Response.Cookies.Append("auth_token", resultRefreshToken.Token, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict
        });

        return Ok(new
        {
            Message = "Refresh successful.",
            Token = resultRefreshToken.Token,
            RefreshToken = refreshToken,
        });
        
    }
    [HttpPost("revokeTokens")] 
    public async Task<IActionResult> RevokeAllUserTokens(Guid userId)
    {
        return Ok();
    }
    [HttpPost("revokeKey")] 
    public async Task<IActionResult> Revoke(Guid userId)
    {
        /*
        try
        {
            await _authService.RevokeUserSecret(request.UserId);
            return Ok(new { Message = "Clave revocada exitosamente." });
        }
        catch (Exception ex)
        {
            return BadRequest(new { Message = "Error al revocar la clave.", Error = ex.Message });
        }
        */
        return Ok();
    }
}