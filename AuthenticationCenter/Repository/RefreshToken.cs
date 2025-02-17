using AuthenticationCenter.Interfaces;
using AuthenticationCenter.Models;

namespace AuthenticationCenter.Repository;

public class RefreshToken : IRefreshToken
{
    private readonly DapperManager _dapperManager;

    public RefreshToken(DapperManager dapperManager)
    {
        _dapperManager = dapperManager;
    }
    
    
    public async Task<User> GetUserRegister(Guid userId)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            string userQuery =
                "SELECT Id, PasswordHash, SaltHash, UserKey ,Email, SecurityStamp, EmailConfirmed, LockoutEnd FROM Users WHERE Id = @Id";
            var user = await _dapperManager
                .QuerySingleAsync<(Guid Id, string PasswordHash, string SaltHash,string UserKey, string Email, string SecurityStamp,
                    bool EmailConfirmed, DateTime?
                    LockoutEnd)>(userQuery, new { Id = userId });

            return new User()
            {
                Id = user.Id,
                PasswordHash = user.PasswordHash,
                SaltHash = user.SaltHash,
                UserKey = user.UserKey,
                Email = user.Email,
                SecurityStamp = user.SecurityStamp,
                EmailConfirmed = user.EmailConfirmed,
                LockoutEnd = user.LockoutEnd
            };

        }
        catch (Exception e)
        {
            return new User();
        }
        finally
        {
            await _dapperManager.CloseConnectionAsync();
        }
    }

    public async Task<TokenQuery> GetRefreshToken(string token)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            string userQuery =
                "SELECT JwtId, Token, AddedDate ,ExpiryDate, IsRevoked, IsUsed, UserId FROM RefreshTokens WHERE Token = @Token";
            var tokenResponse= await _dapperManager
                .QuerySingleAsync<(string JwtId, string Token, DateTime AddedDate, DateTime ExpiryDate, bool IsRevoked, bool IsUsed, Guid UserId)>(userQuery, new { Token = token });

            return new TokenQuery
            {
                UserId = tokenResponse.UserId,
                Token = tokenResponse.Token,
                JwtId = tokenResponse.JwtId,
                IsUsed = tokenResponse.IsUsed,
                IsRevoked = tokenResponse.IsRevoked,
                AddedDate = tokenResponse.AddedDate,
                ExpiryDate = tokenResponse.ExpiryDate
            };

        }
        catch (Exception e)
        {
            return new TokenQuery();
        }
        finally
        {
            await _dapperManager.CloseConnectionAsync();
        }
    }

    public async Task<bool> SetStatusToken(Guid userId, string token)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            await _dapperManager.BeginTransactionAsync();
            string confirmEmailQuery = "UPDATE RefreshTokens  SET IsUsed = 1 WHERE Token = @Token AND UserId = @UserId";
            int rowAffected = await _dapperManager.Execute(confirmEmailQuery, new
            {
                UserId = userId,
                Token = token
            });
            
            if (rowAffected > 0)
            {
                await  _dapperManager.CommitAsync();
                return true;
            }
            else
            {
                await _dapperManager.RollbackAsync();
                return false;
            }

        }
        catch (Exception e)
        {
            return false;
        }
        finally
        {
            await _dapperManager.CloseConnectionAsync();
        }
    }
}