namespace Auth_Service.Settings;

public class JwtSettings
{
    public string Secret { get; set; } = string.Empty;
    public string Issuer { get; set; } = "simos";
    public string Audience { get; set;} = "simos_users";
    public int ExpiryMinutes { get; set; } = 60;
}
