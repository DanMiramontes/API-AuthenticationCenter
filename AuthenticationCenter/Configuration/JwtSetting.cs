namespace AuthenticationCenter.Configuration;

public class JwtSetting
{
    public string Secret { get; set; }
    public TimeSpan ExpiryTime { get; set; }
}