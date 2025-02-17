using AuthenticationCenter.Models;

namespace AuthenticationCenter.Interfaces;

public interface IRefreshToken
{
    Task<User> GetUserRegister(Guid userId);
    
    Task<TokenQuery> GetRefreshToken(string token);
    
    Task<bool>SetStatusToken(Guid userId, string token);
}