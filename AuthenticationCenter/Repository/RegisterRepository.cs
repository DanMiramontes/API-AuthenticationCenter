using AuthenticationCenter.Interfaces;

namespace AuthenticationCenter.Repository;

public class RegisterRepository : IRegisterRepository
{
    private readonly DapperManager _dapperManager;

    public RegisterRepository(DapperManager dapperManager)
    {
        _dapperManager = dapperManager;
    }
    
    
    public async Task<bool> GetEmailRegister(string email)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            string emailQuery = $@"SELECT Email FROM Users WHERE Email = @Email";
            string result = await _dapperManager.QuerySingleAsync<string>(emailQuery, new { Email = email });
             
            return result != null;
             
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

    public async Task<string> EmailRegister(Guid userId)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            string emailQuery = $@"SELECT Email FROM Users WHERE Id = @Id";
            string result = await _dapperManager.QuerySingleAsync<string>(emailQuery, new { Id = userId });

            return result ?? "";

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

    public async Task<Guid> InsertUser(string name, string email, string passwordHash, string saltHash, Guid SecurityStamp,
        Guid ConcurrencyStamp, string tokenHash)
    {
        try
        {
           await _dapperManager.OpenConnectionAsync();
           await _dapperManager.BeginTransactionAsync();
            string insertUserQuery = "INSERT INTO Users (UserName, Email,PasswordHash,SaltHash,SecurityStamp,ConcurrencyStamp) OUTPUT INSERTED.Id VALUES (@Name, @Email,@PasswordHash,@SaltHash,@SecurityStamp,@ConcurrencyStamp)";
            Guid userId = await _dapperManager.ExecuteScalarAsync<Guid>(insertUserQuery, 
                new
                {
                    Name = name, 
                    Email = email, 
                    PasswordHash = passwordHash,
                    SaltHash = saltHash,
                    SecurityStamp = SecurityStamp,
                    ConcurrencyStamp = ConcurrencyStamp
                });

            if (userId == Guid.Empty)
            {
                await _dapperManager.RollbackAsync();
                return Guid.Empty;
            }
            
            string insertTokenQuery = 
                "INSERT INTO EmailVerifications (UserId, Token, ExpirationDate) OUTPUT INSERTED.Id VALUES (@UserId, @Token, @ExpirationDate)";
           int register = await _dapperManager.ExecuteScalarAsync<int>(insertTokenQuery, new
            {
                UserId = userId,
                Token = tokenHash,
                ExpirationDate = DateTime.Now.AddMinutes(25)
            });

            if (register == 0)
            {
                await _dapperManager.RollbackAsync();
                return Guid.Empty;
            }
            
            await _dapperManager.CommitAsync();
            return userId;
        }
        catch (Exception ex)
        {
            await _dapperManager.RollbackAsync();
            return Guid.Empty;
        }
        finally
        {
             await _dapperManager.CloseConnectionAsync();
            
        }
    }


    public async Task<bool> InsertEmailVerification(Guid userId, string tokenHash)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            await _dapperManager.BeginTransactionAsync();
            string insertTokenQuery =
                "INSERT INTO EmailVerifications (UserId, Token, ExpirationDate) OUTPUT INSERTED.Id VALUES (@UserId, @Token, @ExpirationDate)";
            int register = await _dapperManager.ExecuteScalarAsync<int>(insertTokenQuery, new
            {
                UserId = userId,
                Token = tokenHash,
                ExpirationDate = DateTime.Now.AddMinutes(25)
            });

            if (register == 0)
            {
                await _dapperManager.RollbackAsync();
                return false;
            }

            await _dapperManager.CommitAsync();
            return true;
        }
        catch (Exception e)
        {
            await _dapperManager.RollbackAsync();
            return false;
        }
        finally
        {
            await _dapperManager.CloseConnectionAsync();
        }

    }
    public async Task<DateTime> GetLockoutEnd(Guid userId)
    {
        
        try
        {
            
           await _dapperManager.OpenConnectionAsync();
            string checkLockQuery = "SELECT LockoutEnd FROM Users WHERE Id = @UserId";

             DateTime userStatus = await _dapperManager.QuerySingleAsync<DateTime>(checkLockQuery,
                new { UserId = userId });
            
            
             if (userStatus == null)
             {
                 return DateTime.MinValue;
             }
             return userStatus;
        }
        catch (Exception ex)
        {
            return DateTime.MinValue;

        }
        finally
        {
          await _dapperManager.CloseConnectionAsync();
        }
        
    }

    public async Task<int> GetEmailVerifications(Guid userId, string tokenHash, DateTime date)
    {
        try
        {
           await _dapperManager.OpenConnectionAsync();
            string validateTokenQuery =
                "SELECT COUNT(*) FROM EmailVerifications WHERE UserId = @UserId AND Token = @TokenHash AND ExpirationDate > @Now";
            int validTokenCount = await _dapperManager.ExecuteScalarAsync<int>(validateTokenQuery, new
            {
                UserId = userId,
                TokenHash = tokenHash,
                Now = date
            });
            
            return validTokenCount;

        }
        catch (Exception e)
        {
            return 0;
        }
        finally
        {
            await _dapperManager.CloseConnectionAsync();
        }

    }

    public async Task<bool> IncrementFailures(Guid userId)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            await _dapperManager.BeginTransactionAsync();
            string incrementFailuresQuery =
                "UPDATE Users SET AccessFailedCount = AccessFailedCount + 1, ConcurrencyStamp = @NewConcurrencyStamp WHERE Id = @UserId";
            int rowAffected = await _dapperManager.Execute(incrementFailuresQuery, new
            {
                UserId = userId,
                NewConcurrencyStamp = Guid.NewGuid().ToString()
            });
            
            
            if (rowAffected > 0)
            {
                await _dapperManager.CommitAsync();
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
            await _dapperManager.RollbackAsync();
            return false;
        }
        finally
        {
          await _dapperManager.CloseConnectionAsync();
        }

    }

    public async Task<int> GetFailuresCount(Guid userId)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            string getFailuresQuery = "SELECT AccessFailedCount FROM Users WHERE Id = @UserId";
            int failureCount = await _dapperManager.ExecuteScalarAsync<int>(getFailuresQuery, new
            {
                UserId = userId
            });
            return failureCount;
        }
        catch (Exception e)
        {
            return 0;
        }
        finally
        {
          await _dapperManager.CloseConnectionAsync();
        }

    }

    public  async Task<bool> LockUser(Guid userId, DateTime date)
    {
        try
        {
           await _dapperManager.OpenConnectionAsync();
           await _dapperManager.BeginTransactionAsync();
            string lockUserQuery = "UPDATE Users SET LockoutEnd = @LockoutEnd, ConcurrencyStamp = @NewConcurrencyStamp WHERE Id = @UserId";
           int rowAffected = await _dapperManager.Execute(lockUserQuery, new
            {
                LockoutEnd = date.AddMinutes(15),
                UserId = userId,
                NewConcurrencyStamp = Guid.NewGuid().ToString()
            });
            if (rowAffected > 0)
            {
                await _dapperManager.CommitAsync();
                return true;
            }
            await _dapperManager.RollbackAsync();
            return false;
        }
        catch (Exception e)
        {
            try
            {
                await _dapperManager.RollbackAsync();
            }
            catch (Exception exception)
            {
               
                // looger
            }
            return false;
        }
        finally
        {
          await _dapperManager.CloseConnectionAsync();
        }
    }

    public async Task<bool> ConfirmEmail(Guid userId)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();
            await _dapperManager.BeginTransactionAsync();
            string confirmEmailQuery = "UPDATE Users SET EmailConfirmed = 1, AccessFailedCount = 0, ConcurrencyStamp = @NewConcurrencyStamp WHERE Id = @UserId";
            int rowAffected = await _dapperManager.Execute(confirmEmailQuery, new
            {
                UserId = userId,
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

    public async Task<bool> DeleteTokenEmail(Guid userId, string tokenHash)
    {
        try
        {
            await _dapperManager.OpenConnectionAsync();   
            await _dapperManager.BeginTransactionAsync();
            string deleteTokenQuery = "DELETE FROM EmailVerifications WHERE UserId = @UserId AND Token = @TokenHash";
            int rowAffected = await  _dapperManager.Execute(deleteTokenQuery, 
                new { UserId = userId, TokenHash = tokenHash });
            
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
}
    