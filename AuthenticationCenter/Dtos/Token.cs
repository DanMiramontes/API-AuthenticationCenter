using System.ComponentModel.DataAnnotations;

namespace AuthenticationCenter.Dtos;

public class TokenRequest
{
    [Required]
    public string Token { get; set; }
    [Required]
    public string RefreshToken { get; set; }
}