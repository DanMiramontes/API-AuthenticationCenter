namespace AuthenticationCenter.Models;

public class User
{
    public Guid Id { get; set; }
    public string PasswordHash { get; set; }
   
    public string? UserKey { get; set; }
    public string SaltHash { get; set; }
    public string Email { get; set; }
    public string SecurityStamp { get; set; }
    public bool EmailConfirmed { get; set; }
    public DateTime? LockoutEnd { get; set; }
}