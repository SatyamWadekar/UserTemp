using Microsoft.Extensions.Options;
using MongoDB.Driver;
using UserTemp.Model;

namespace UserTemp.Services
{
    public class OrganizationService : BaseService<Organization>
    {
        public OrganizationService(IOptions<DBSetting> orgDatabaseSettings)
        {
            var mongoClient = new MongoClient(
                orgDatabaseSettings.Value.ConnectionString);

            var mongoDatabase = mongoClient.GetDatabase(
                orgDatabaseSettings.Value.DatabaseName);

            if (orgDatabaseSettings.Value.OrganizationCollectionName is not null)
            {
                _Collection = mongoDatabase.GetCollection<Organization>(orgDatabaseSettings.Value.OrganizationCollectionName);
            }
        }

        public async Task<List<Organization>> GetAsync(string userId) =>
            await _Collection.Find(x => x.OrganizationMembers.Contains(userId) && x.IsActive).ToListAsync();

        public async Task<Organization?> GetAsync(string id, string userId) =>
            await _Collection.Find(x => x.Id == id && x.OrganizationMembers.Contains(userId) && x.IsActive).FirstOrDefaultAsync();


        public async Task<Organization?> GetByNameAsync(string name, string userId) =>
            await _Collection.Find(x => x.Name == name && x.OrganizationOwner == userId && x.IsActive).FirstOrDefaultAsync();

        public async Task<Organization> GetOrg(string? orgId) =>
            await _Collection.Find(x => x.Id == orgId && x.IsActive).FirstOrDefaultAsync();

        public async Task UpdateAsync(string id, Organization updatedOrganization) =>
        await _Collection.ReplaceOneAsync(x => x.Id == id, updatedOrganization);

        public async Task RemoveByNameAsync(string organizationname) =>
            await _Collection.DeleteOneAsync(x => x.Name == organizationname);
    }
}
