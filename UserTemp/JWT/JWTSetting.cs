namespace UserTemp.JWT
{
    public class JwtSettings
    {
        public bool ValidateIssuerSigningKey { get; set; }

        public string IssuerSigningKey { get; set; } = string.Empty;
        public bool ValidateIssuer { get; set; } = true;
        public string ValidIssuer { get; set; } = string.Empty;
        public bool ValidateAudience { get; set; } = true;
        public string ValidAudience { get; set; } = string.Empty;
        public bool RequireExpirationTime { get; set; }
        public bool ValidateLifetime { get; set; } = true;
    }

    public class UserTokens
    {
        public string Token { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public TimeSpan Validaty { get; set; }
        public string RefreshToken { get; set; } = string.Empty;
        public string? Id { get; set; }
        public string EmailId { get; set; } = string.Empty;
        public Guid GuidId { get; set; }
        public DateTime ExpiredTime { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
        public string OrganizationId { get; set; } = string.Empty;
    }

    public class TokenApiModel
    {
        public string? AccessToken { get; set; }
        public string? RefreshToken { get; set; }
    }
}
