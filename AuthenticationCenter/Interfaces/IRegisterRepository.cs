namespace AuthenticationCenter.Interfaces;

public interface IRegisterRepository
{
    Task<bool> GetEmailRegister(string email);

    Task<string> EmailRegister(Guid userId);
    
    Task<Guid> InsertUser(string name, string email, string passwordHash, string saltHash, Guid SecurityStamp, Guid ConcurrencyStamp, string tokenHash);

    Task<bool> InsertEmailVerification(Guid userId, string tokenHash);
    Task<DateTime> GetLockoutEnd(Guid userId);
    
    Task<int> GetEmailVerifications(Guid userId, string tokenHash, DateTime date);
    
    Task<bool> IncrementFailures(Guid userId);
    
    Task<int> GetFailuresCount(Guid userId);
    
    Task<bool> LockUser(Guid userId, DateTime date);
    
    Task<bool> ConfirmEmail(Guid userId);
    
    Task<bool> DeleteTokenEmail(Guid userId, string tokenHash);

    
}
