namespace AuthenticationCenter.Models;

public class AuthResult
{
    public string? Token { get; set; }
    public RefreshToken? RefreshToken { get; set; }
    public bool Result { get; set; }
    public string? Message { get; set; }
}