using Newtonsoft.Json.Linq;

namespace UserTemp.Helper
{
    public static class Commonhelper
    {
        public static bool PathchObject(JObject jsonObject, object sourceObject)
        {
            var flag = false;
            if (jsonObject is not null && jsonObject.Count > 0)
            {
                foreach(var item in jsonObject)
                {
                    var key = item.Key;

                    var propertyInfo = sourceObject.GetType().GetProperty(key);
                    if (propertyInfo is not null)
                    {
                        var value = propertyInfo.GetValue(sourceObject, null);
                        var setValue = Convert.ChangeType(item.Value.ToString(), propertyInfo.PropertyType);

                        if (value is null || value.ToString() != setValue.ToString())
                        {
                            propertyInfo.SetValue(sourceObject, setValue, null);
                            flag = true;
                        }
                    }

                }
            }

            return flag;
        }
    }
}
