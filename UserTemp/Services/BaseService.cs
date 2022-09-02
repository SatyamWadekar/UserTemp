using MongoDB.Driver;
using System.Security.Cryptography;

namespace UserTemp.Services
{
    public class BaseService<T> where T : class
    {
        public static IMongoCollection<T> _Collection { get; set; }


        public async Task<List<T>> GetAsync() =>
            await _Collection.Find(_ => true).ToListAsync();

        public async Task CreateAsync(T newT) =>
            await _Collection.InsertOneAsync(newT);

        public string RandomStringGenerator(int byteSize = 64, int stringSize = 24)
        {
            var randomNumber = new byte[byteSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return
                    Convert.ToBase64String(randomNumber)
                    .Replace("/", "")
                    .Replace("+", "")
                    .Replace("=", "")
                    .Substring(0, stringSize);
            }
        }
    }
}
