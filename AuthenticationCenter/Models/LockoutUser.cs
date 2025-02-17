namespace AuthenticationCenter.Models;

public class LockoutUser
{
    public DateTime? LockoutEnd { get; set; }
    public string SecurityStamp { get; set; }
}