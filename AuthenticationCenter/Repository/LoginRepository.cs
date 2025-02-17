using AuthenticationCenter.Interfaces;
using AuthenticationCenter.Models;

namespace AuthenticationCenter.Repository;

public class LoginRepository : ILoginRepository
{
    private readonly DapperManager _dapperManager;

    public LoginRepository(DapperManager dapperManager)
    {
        _dapperManager = dapperManager;
    }
    
    public async Task<User> GetUserRegister(string email)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            string userQuery =
                "SELECT Id, PasswordHash, SaltHash, UserKey ,Email, SecurityStamp, EmailConfirmed, LockoutEnd FROM Users WHERE Email = @Email";
            var user = await _dapperManager
                .QuerySingleAsync<(Guid Id, string PasswordHash, string SaltHash,string UserKey, string Email, string SecurityStamp,
                    bool EmailConfirmed, DateTime?
                    LockoutEnd)>(userQuery, new { Email = email });

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

    public async Task<string> CheckExistingNonceQuery(Guid userId, DateTime now)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            string checkExistingNonceQuery = "SELECT Nonce FROM Nonces WHERE UserId = @UserId AND ExpirationDate > @Now";
            var existingNonce =  await _dapperManager.QuerySingleAsync<Guid>(checkExistingNonceQuery, new
            {
                UserId = userId,
                Now = now
            });
            if (!string.IsNullOrEmpty(existingNonce.ToString()))
            {
                return "";
            }

            return existingNonce.ToString();
        }
        catch (Exception e)
        {
            return "";
        }
        finally
        {
            await _dapperManager.CloseConnectionAsync();
        }
    }

    public async Task<bool> InvalidateNonceQuery(Guid userId)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();   
            await _dapperManager.BeginTransactionAsync();
            string invalidateNonceQuery = "DELETE FROM Nonces WHERE UserId = @UserId";
            int rowAffected = await _dapperManager.Execute(invalidateNonceQuery, new { UserId = userId});
            if (rowAffected > 0)
            {
                await _dapperManager.CommitAsync();
                return true;
            }
            else
            {
                await  _dapperManager.RollbackAsync();
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

    public  async Task<bool> SetKeyUserRegister(Guid userId, string key)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            await _dapperManager.BeginTransactionAsync();
            string setKey = "UPDATE Users SET UserKey = @UserKey, ConcurrencyStamp = @NewConcurrencyStamp WHERE Id = @UserId";
            int rowAffected = await _dapperManager.Execute(setKey, new
            {
                UserId = userId,
                UserKey = key,
                NewConcurrencyStamp = Guid.NewGuid().ToString()
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

    public  async Task<bool> SetNonce(Guid userId, string nonce, DateTime now)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            await _dapperManager.BeginTransactionAsync();
            string storeNonceQuery = "INSERT INTO Nonces (UserId, Nonce, ExpirationDate) VALUES (@UserId, @Nonce, @ExpirationDate)";
            int rowAffected = await _dapperManager.Execute(storeNonceQuery, new
            {
                UserId = userId,
                Nonce = nonce,
                ExpirationDate = DateTime.Now.AddMinutes(15) // Expiración de 15 minutos
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

    public  async Task<string> GetKeyser(Guid userId)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            string userKey =
                "SELECT UserKey FROM Users WHERE Id = @Id";
            var user = await _dapperManager
                .QuerySingleAsync<string>(userKey, new { Id = userId });
            
            return user ?? "";
        }
        catch (Exception e)
        {
            return "";
        }
        finally
        {
            await _dapperManager.CloseConnectionAsync();
        }
    }

    public async Task<bool> InsertRefreshToken(string UserId, string Token, string JwtId, bool IsUsed, bool IsRevoked,
        DateTime AddedDate, DateTime ExpiryDate)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            await _dapperManager.BeginTransactionAsync();
            string insertRefreshTokenQuery = "INSERT INTO RefreshTokens (JwtId, Token, AddedDate, ExpiryDate, IsRevoked, IsUsed, UserId) VALUES (@JwtId, @Token, @AddedDate, @ExpiryDate, @IsRevoked, @IsUsed, @UserId)";
            int rowAffected = await _dapperManager.Execute(insertRefreshTokenQuery, new
            {
                JwtId = JwtId,
                Token = Token,
                AddedDate = AddedDate, 
                ExpiryDate = ExpiryDate,
                IsRevoked = IsRevoked,
                IsUsed = IsUsed, 
                UserId = UserId
                
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