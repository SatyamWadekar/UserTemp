using System.ComponentModel;
using System.Text.Json.Serialization;

namespace UserTemp.Data.Enums
{
    [JsonConverter(typeof(JsonStringEnumConverter))]
    public enum EnvironmentEnum
    {
        [Description("Production")]
        Production,
        [Description("Stage")]
        Stage,
        [Description("Development")]
        Development
    }
}