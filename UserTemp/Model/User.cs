
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using UserTemp.Data.Enums;

namespace UserTemp.Model
{
    public class User : Common
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        [JsonIgnore]
        public string? Id { get; set; }

        [BsonElement("Name")]
        [JsonPropertyName("fullName")]
        [Required]
        public string fullName { get; set; } = null!;

        [DataType(DataType.EmailAddress)]
        [Required]
        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [JsonIgnore]
        public string Password { get; set; } = string.Empty;

        [Required]
        public EnvironmentEnum Role { get; set; } = EnvironmentEnum.Development;
        [JsonPropertyName("PhoneNumber")]
        public string PhoneNumber { get; set; } = string.Empty;

        public bool IsMultiFactorAuthentication { get; set; }

        public MultiFactorAuthentication MultiFactorAuthentication { get; set; } = new MultiFactorAuthentication();

        public bool IsOrganizationOwner { get; set; }

        [Required]
        [JsonPropertyName("organizationName")]
        public string OrganizationName { get; set; } = string.Empty;

        [JsonPropertyName("organization")]
        public Dictionary<string, bool> Organization { get; set; } = new Dictionary<string, bool>();

        public bool IsPHIAccess { get; set; }
        public string ProfileImage { get; set; } = string.Empty;
        [JsonIgnore]
        public string? RefreshToken { get; set; }
        [JsonIgnore]
        public DateTime? RefreshTokenExpiryTime { get; set; }
        [JsonIgnore]
        public bool IsVerified { get; set; } = true;
    }

    public class ChangePassword
    {
        [Required]
        [JsonPropertyName("email")]
        public string Email { get; set; } = string.Empty;
        [JsonPropertyName("currentPassword")]
        public string CurrentPassword { get; set; } = string.Empty;
        [JsonPropertyName("newPassword")]
        public string NewPassword { get; set; } = string.Empty;
        [JsonPropertyName("confirmPassword")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }

    public class MultiFactorAuthentication
    {
        [JsonPropertyName("method")]
        public string Method { get; set; } = string.Empty;
        [JsonPropertyName("countryCode")]
        public string CountryCode { get; set; } = string.Empty;
        [JsonPropertyName("phoneNumber")]
        public string PhoneNumber { get; set; } = string.Empty;
    }

    public class LogInUser
    {
        [Required]
        [JsonPropertyName("email")]
        public string Email { set; get; }
        [Required]
        [JsonPropertyName("password")]
        public string Password { set; get; }
    }

    public class RegisterUser
    {
        [BsonElement("Name")]
        [JsonPropertyName("fullName")]
        public string? Name { get; set; } = null!;

        [DataType(DataType.EmailAddress)]
        [Required]
        [JsonPropertyName("email")]
        public string Email { get; set; }

        [Required]
        [JsonPropertyName("password")]
        public string Password { get; set; }

    }

    public class AddUser
    {
        [Required]
        [JsonPropertyName("fullName")]
        public string Name { get; set; }
        [Required]
        [JsonPropertyName("email")]
        public string Email { get; set; }
        [Required]
        [JsonPropertyName("role")]
        public EnvironmentEnum Role { get; set; } = EnvironmentEnum.Development;
        [Required]
        [JsonPropertyName("organizationId")]
        public string OrganizationId { get; set; }

    }

    public class ResetPassword
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        [JsonIgnore]
        public string? Id { get; set; }

        [JsonIgnore]
        [JsonPropertyName("organizationId")]
        public string OrganizationId { get; set; } = string.Empty;

        [JsonIgnore]
        public string Email { set; get; } = string.Empty;

        [JsonPropertyName("token")]
        public string Token { get; set; } = string.Empty;

        [JsonIgnore]
        public DateTime TokenCreatedAt { get; set; } = DateTime.MinValue;

        [JsonIgnore]
        public DateTime TokenValideTill { get; set; } = DateTime.MinValue;

        [JsonPropertyName("newPassword")]
        public string NewPassword { get; set; } = string.Empty;

        [JsonPropertyName("confirmPassword")]
        public string ConfirmPassword { get; set; } = string.Empty;
        [JsonIgnore]
        public bool CanVerifyUser { get; set; } = false;

    }

    public class RemoveInvitation
    {
        [Required]
        [JsonPropertyName("email")]
        public string Email { get; set; }
        [Required]
        [JsonPropertyName("organizationId")]
        public string OrganizationId { get; set; }
    }

    public class UpdateUser
    {
        [JsonPropertyName("fullName")]
        public string Name { get; set; }

        [JsonPropertyName("phoneNumber")]
        public string PhoneNumber { get; set; } = string.Empty;
    }
}
