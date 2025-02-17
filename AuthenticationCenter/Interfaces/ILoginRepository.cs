using AuthenticationCenter.Models;

namespace AuthenticationCenter.Interfaces;

public interface ILoginRepository
{
    Task<User> GetUserRegister(string email);

    Task<string> CheckExistingNonceQuery(Guid userId, DateTime now);

    Task<bool> InvalidateNonceQuery(Guid userId);

    Task<bool> SetKeyUserRegister(Guid userId, string key);

    Task<bool> SetNonce(Guid userId, string nonce, DateTime now);

    Task<String> GetKeyser(Guid userId);

    Task<bool> InsertRefreshToken(string UserId, string Token, string JwtId, bool IsUsed, bool IsRevoked,
        DateTime AddedDate, DateTime ExpiryDate);
}