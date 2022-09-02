using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace UserTemp.JWT
{
    public static class JwtHelpers
    {
        public static IEnumerable<Claim> GetClaims(this UserTokens userAccounts, Guid Id)
        {
            IEnumerable<Claim> claims = new Claim[] {
                new Claim("Id", userAccounts.Id.ToString()),
                new Claim(ClaimTypes.Name, userAccounts.UserName),
                new Claim(ClaimTypes.Email, userAccounts.EmailId),
                new Claim(ClaimTypes.NameIdentifier, Id.ToString()),
                new Claim(ClaimTypes.Expiration, DateTime.Now.AddHours(1).ToString("MMM ddd dd yyyy HH:mm:ss tt"))
            };
            return claims;
        }

        public static IEnumerable<Claim> GetClaims(this UserTokens userAccounts, out Guid Id)
        {
            Id = Guid.NewGuid();
            return GetClaims(userAccounts, Id);
        }
        public static UserTokens GenTokenkey(UserTokens model, JwtSettings jwtSettings)
        {
            try
            {
                var userToken = new UserTokens();
                if (model == null) throw new ArgumentException(nameof(model));
                var key = System.Text.Encoding.ASCII.GetBytes(jwtSettings.IssuerSigningKey);
                Guid Id = Guid.Empty;

                DateTime expireTime = DateTime.Now.AddHours(1);
                userToken.Validaty = expireTime.TimeOfDay;

                SymmetricSecurityKey securityKey = new SymmetricSecurityKey(key);
                SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(GetClaims(model, out Id)),
                    Expires = expireTime,
                    SigningCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256),
                    Issuer = jwtSettings.ValidIssuer,
                    Audience = jwtSettings.ValidAudience,
                    NotBefore = new DateTimeOffset(DateTime.Now).DateTime
                };

                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                JwtSecurityToken token = handler.CreateJwtSecurityToken(descriptor);

                userToken.Token = new JwtSecurityTokenHandler().WriteToken(token);
                userToken.Id = model.Id;
                userToken.GuidId = Id;
                userToken.UserName = model.EmailId;

                return userToken;
            }
            catch (Exception)
            {
                throw;
            }
        }

        public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token, JwtSettings jwtSettings)
        {
            var key = System.Text.Encoding.ASCII.GetBytes(jwtSettings.IssuerSigningKey);

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");
            return principal;
        }

        public static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return
                    Convert.ToBase64String(randomNumber)
                    .Replace("/", "");
            }
        }

        public static UserTokens GenResetPasswordTokenkey(UserTokens model, JwtSettings jwtSettings)
        {
            try
            {
                var userToken = new UserTokens();
                Guid Id = Guid.Empty;

                DateTime expireTime = DateTime.Now.AddHours(12);
                userToken.Validaty = expireTime.TimeOfDay;

                userToken.Token = GenerateRefreshToken();
                userToken.Id = model.Id;
                userToken.GuidId = Id;
                userToken.UserName = model.EmailId;
                userToken.ExpiredTime = expireTime;

                return userToken;
            }
            catch (Exception)
            {
                throw;
            }
        }

    }

}
