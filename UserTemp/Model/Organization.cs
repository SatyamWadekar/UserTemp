using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace UserTemp.Model
{
    public class Organization
    {
        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        [JsonIgnore]
        public string? Id { get; set; }
        [BsonElement("Name")]
        [JsonPropertyName("organizationName")]
        public string Name { get; set; }
        [JsonIgnore]
        public List<string?> OrganizationMembers { get; set; } = new List<string?>();
        [JsonIgnore]
        public string? OrganizationOwner { get; set; }
        [JsonPropertyName("overview")]
        public string Overview { get; set; }
        [JsonPropertyName("alertEmail")]
        public string AlertEmail { get; set; }
        [JsonPropertyName("salesEmail")]
        public string SalesEmail { get; set; }
        [JsonPropertyName("phoneNumber")]
        public string PhoneNumber { get; set; }
        [JsonPropertyName("webSite")]
        public string WebSite { get; set; }
        [JsonPropertyName("twitter")]
        public string Twitter { get; set; }
        [JsonPropertyName("category")]
        public List<string> Category { get; set; } = new List<string>();
        public string Logo { get; set; } = string.Empty;
        [JsonIgnore]
        public bool IsActive { get; set; } = true;
    }

    public class CreateOrganization
    {
        [Required]
        [JsonPropertyName("organizationName")]
        public string Name { get; set; }
        [Required]
        [JsonPropertyName("userId")]
        public string? UserId { get; set; }
    }

    public class OrganizationIds
    {
        [JsonPropertyName("organizationId")]
        public string? OrganizationId { get; set; }
    }

    public class IdAndOrgId : OrganizationIds
    {
        public string? Id { get; set; }
    }

    public class StringId
    {
        public string? Id { get; set; }
    }
}
