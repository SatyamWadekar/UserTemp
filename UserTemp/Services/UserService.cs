using Microsoft.Extensions.Options;
using MongoDB.Driver;
using System.Text.RegularExpressions;
using UserTemp.Data.Enums;
using UserTemp.JWT;
using UserTemp.Mail;
using UserTemp.Model;
using UserTemp.Model.Enums;

namespace UserTemp.Services
{
    public class UserService : BaseService<User>
    {
        private readonly OrganizationService _organizationService;
        private readonly ResetPasswordService _resetPasswordService;
        private readonly IConfiguration configuration;
        private readonly string EnvirnmentVariable;
        private readonly JwtSettings jwtSettings;

        public UserService(IOptions<DBSetting> userDatabaseSettings, IMailService mailService, JwtSettings jwtSettings, IConfiguration iConfig)
        {
            var mongoClient = new MongoClient(
                userDatabaseSettings.Value.ConnectionString);

            var mongoDatabase = mongoClient.GetDatabase(
                userDatabaseSettings.Value.DatabaseName);

            Console.WriteLine("Name of collection");
            Console.WriteLine(userDatabaseSettings.Value.UsersCollectionName);

            if (userDatabaseSettings.Value.UsersCollectionName is not null)
            {
                _Collection = mongoDatabase.GetCollection<User>(userDatabaseSettings.Value.UsersCollectionName);
            }

            configuration = iConfig;
            this.jwtSettings = jwtSettings;
            _organizationService = new OrganizationService(userDatabaseSettings);
            _resetPasswordService = new ResetPasswordService(userDatabaseSettings, mailService, jwtSettings, iConfig);
            EnvirnmentVariable = "DevSetting";
        }

        public async Task CreateUser(User user)
        {
            await _Collection.InsertOneAsync(user);
        }

        public async Task AddExistingUser(AddUser addUser, string userId)
        {
            var validOrg = await _organizationService.GetOrg(addUser.OrganizationId);

            if (validOrg is not null && validOrg.Id is not null && validOrg.OrganizationOwner == userId)
            {

                var validEmail = await ValidateEmailWithOrganization(addUser.Email, addUser.OrganizationId);

                if (validEmail is not null)
                {
                    validEmail.Organization.Add(validOrg.Id, false);
                    await _Collection.ReplaceOneAsync(x => x.Id == validEmail.Id, validEmail);

                    if (validOrg.Id is not null)
                    {
                        validOrg.OrganizationMembers.Add(validEmail.Id);
                        await _organizationService.UpdateAsync(validOrg.Id, validOrg);
                    }

                    var token = await _resetPasswordService.GenerateTokenForResetPassword(validEmail, validOrg.Id);
                    if (token is not null)
                    {
                        await _resetPasswordService.SendMail(token, EmailType.VerifyEmail, userName: addUser.Name);
                    }

                }
            }
        }

        public async Task CreateUser(AddUser addUser, string userId)
        {
            var validOrg = await _organizationService.GetOrg(addUser.OrganizationId);

            if (validOrg is not null && validOrg.OrganizationOwner == userId)
            {
                var user = new User
                {
                    fullName = addUser.Name,
                    Email = addUser.Email,
                    Role = addUser.Role,
                    Organization = new Dictionary<string, bool>
                    {
                            {
                                addUser.OrganizationId,
                                false
                            }
                    },
                    IsVerified = false
                };
                var validEmail = await ValidateEmail(addUser.Email);

                if (validEmail is null)
                {
                    await _Collection.InsertOneAsync(user);
                    if (validOrg.Id is not null)
                    {
                        validOrg.OrganizationMembers.Add(user.Id);
                        await _organizationService.UpdateAsync(validOrg.Id, validOrg);
                    }

                    var token = await _resetPasswordService.GenerateTokenForResetPassword(user, addUser.OrganizationId);
                    if (token is not null)
                    {
                        await _resetPasswordService.SendMail(token, EmailType.CreatePasswordEmail, true, addUser.Name);
                    }

                }
            }
        }

        public async Task<User> LogIn(LogInUser logInUser)
        {
            var user = new User
            {
                Email = logInUser.Email,
                Password = Masking.GetEncryptedString(logInUser.Password, configuration.GetValue<string>(String.Format("{0}:salt", EnvirnmentVariable)))
            };
            var validationResult = await ValidateEmailAndPasswordAsync(user);
            var result = new User();
            if (validationResult != null)
            {
                result = validationResult;
            }
            return result;
        }

        public async Task<User?> ValidateEmailAndPasswordAsync(User user) =>
            await _Collection.Find(x => x.Email == user.Email && x.Password == user.Password && x.IsActive && x.IsVerified).FirstOrDefaultAsync();

        public User? ValidateEmailAndPassword(User user)
        {
            return _Collection.Find(x => x.Email == user.Email && x.Password == user.Password && x.IsActive && x.IsVerified).FirstOrDefault();
        }

        public async Task<User?> ValidateEmail(string eMail)
        {
            try
            {
                var tempResult = await _Collection.Find(x => x.Email == eMail && x.IsActive).FirstOrDefaultAsync();

                var match = Regex.Match(eMail, "^([a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,15}|[0-9]{1,15})(\\]?)$", RegexOptions.IgnoreCase);

                if (tempResult is not null && match.Success)
                {
                    return tempResult;
                }
                else
                {
                    return null;
                }
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public async Task<bool?> IsEmailValid(string email)
        {
            try
            {
                return await _Collection.Find(x => x.Email == email && x.IsActive).AnyAsync();

            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public async Task<User?> ValidateEmailWithOrganization(string email, string orgId) =>
            await _Collection.Find(x => x.Email == email && x.IsActive && !x.Organization.ContainsKey(orgId)).FirstOrDefaultAsync();

        public async Task<User?> ValidateNotVerifiedEmail(string eMail) =>
            await _Collection.Find(x => x.Email == eMail && x.IsActive && !x.IsVerified).FirstOrDefaultAsync();

        public async Task<User?> GetAsync(string id) =>
        await _Collection.Find(x => x.Id == id && x.IsActive).FirstOrDefaultAsync();

        public async Task<User?> GetByOrgIdAsync(string id, string orgId) =>
            await _Collection.Find(x => x.Id == id && x.Organization.ContainsKey(orgId) && x.IsActive && x.Organization[orgId]).FirstOrDefaultAsync();

        public async Task<List<User>> GetVerifiedUserByOrgIdAsync(string orgId) =>
            await _Collection.Find(x => x.Organization.ContainsKey(orgId) && x.IsActive && x.Organization[orgId]).ToListAsync();

        public async Task<List<User>> GetNotVerifiedUserByOrgIdAsync(string orgId) =>
            await _Collection.Find(x => x.Organization.ContainsKey(orgId) && x.IsActive && !x.Organization[orgId]).ToListAsync();

        public async Task<User?> GetByNameAsync(string name) =>
            await _Collection.Find(x => x.fullName == name).FirstOrDefaultAsync();

        public async Task<User?> GetByEmailAsync(string email) =>
            await _Collection.Find(x => x.Email == email).FirstOrDefaultAsync();

        public async Task UpdateAsync(string id, User updatedUser) =>
            await _Collection.ReplaceOneAsync(x => x.Id == id, updatedUser);

        public async Task RemoveAsync(string id) =>
            await _Collection.DeleteOneAsync(x => x.Id == id);

        public async Task UpdateMFAAsync(string userId, MultiFactorAuthentication mfa)
        {
            var user = await _Collection.Find(x => x.Id == userId).FirstOrDefaultAsync();

            if (user is not null)
            {
                user.IsMultiFactorAuthentication = true;
                user.MultiFactorAuthentication = mfa;
                await _Collection.ReplaceOneAsync(x => x.Id == userId, user);
            }

        }

        public async Task ChangePassword(ChangePassword changePassword)
        {
            var user = await _Collection.Find(x => x.Email == changePassword.Email).FirstOrDefaultAsync();
            if (user is not null && user.Password == Masking.GetEncryptedString(changePassword.CurrentPassword, configuration.GetValue<string>(String.Format("{0}:salt", EnvirnmentVariable))))
            {
                user.Password = Masking.GetEncryptedString(changePassword.NewPassword, configuration.GetValue<string>(String.Format("{0}:salt", EnvirnmentVariable)));
                await _Collection.ReplaceOneAsync(x => x.Email == changePassword.Email, user);
            }
        }

        public User GetUserByEmail(string email)
        {
            var user = new User();

            user = _Collection.Find(x => x.Email == email).FirstOrDefault();

            return user;
        }
        public async Task ResetPassword(ChangePassword resetPassword, string orgId, bool canChangeVerified = false)
        {
            var user = await _Collection.Find(x => x.Email == resetPassword.Email).FirstOrDefaultAsync();
            if (user is not null)
            {
                if (!string.IsNullOrEmpty(resetPassword.NewPassword) && user.Id is not null)
                {
                    user.Password = Masking.GetEncryptedString(resetPassword.NewPassword, configuration.GetValue<string>(String.Format("{0}:salt", EnvirnmentVariable)));
                }

                if (!string.IsNullOrEmpty(orgId) && user.Organization.ContainsKey(orgId))
                {
                    user.Organization[orgId] = true;
                }

                if (canChangeVerified)
                {
                    user.IsVerified = true;
                }

                await _Collection.ReplaceOneAsync(x => x.Email == resetPassword.Email, user);
            }
        }

        public async Task RemoveInvitation(User validEmail, string orgId)
        {

            if (validEmail is not null && validEmail.Id is not null)
            {
                if (validEmail.Organization.ContainsKey(orgId) && validEmail.Organization.Count > 1)
                {
                    validEmail.Organization.Remove(orgId);
                    var org = await _organizationService.GetAsync(orgId, validEmail.Id);
                    if (org is not null)
                    {
                        org.OrganizationMembers.Remove(validEmail.Id);
                        await _organizationService.UpdateAsync(orgId, org);
                    }

                    await _Collection.ReplaceOneAsync(x => x.Email == validEmail.Email, validEmail);
                }
                else
                {
                    await RemoveAsync(validEmail.Id);
                }

                await _resetPasswordService.RemoveByEmailAsync(validEmail.Email);
            }

        }

        public bool ValidEmailString(string email)
        {
            var match = Regex.Match(email, "^([a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))([a-zA-Z]{2,15}|[0-9]{1,15})(\\]?)$", RegexOptions.IgnoreCase);

            return match.Success;
        }

        public bool ValidPasswordString(string password)
        {
            var match = Regex.Match(password, "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,256}$", RegexOptions.IgnoreCase);

            return match.Success;
        }

        public async Task<User?> GetUserByToken(HttpRequest _request)
        {
            var tokenValue = _request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value;

            var tempToken = tokenValue.ToString().Split(' ');

            string token = tempToken.LastOrDefault();

            if (token is not null)
            {
                var principal = JwtHelpers.GetPrincipalFromExpiredToken(token, jwtSettings);
                if (principal is not null
                    && principal.Identity is not null
                    && principal.Identity.Name is not null)
                {
                    var email = principal.Identity.Name;
                    var user = await GetByEmailAsync(email);
                    if (user is not null)
                    {
                        return user;
                    }

                }
            }

            return null;
        }

        public async Task<bool?> ValidUserEnvirnment(EnvironmentEnum environment, HttpRequest _request)
        {
            try
            {
                var user = await GetUserByToken(_request);

                if (environment < user.Role)
                {
                    return false;
                }
                else
                {
                    return true;
                }
            }
            catch (Exception ex)
            {
                return null;
            }
        }
        public async Task UpdateUserOrgAsync(User currentUser, string orgId, string newOwnerId)
        {
            currentUser.IsOrganizationOwner = false;
            var org = await _organizationService.GetOrg(orgId);
            org.OrganizationOwner = newOwnerId;
            await _organizationService.UpdateAsync(orgId, org);
        }

        public async Task<Organization?> GetOrgById(string orgId)
            => await _organizationService.GetOrg(orgId);


    }

    public class ResetPasswordService : BaseService<ResetPassword>
    {
        private readonly IMailService mailService;
        private readonly JwtSettings jwtSettings;
        private readonly IConfiguration configuration;
        private readonly string EnvirnmentVariable;

        public ResetPasswordService(IOptions<DBSetting> resetPasswordDatabaseSettings, IMailService mailService, JwtSettings jwtSettings, IConfiguration iConfig)
        {
            var mongoClient = new MongoClient(
                resetPasswordDatabaseSettings.Value.ConnectionString);

            var mongoDatabase = mongoClient.GetDatabase(
                resetPasswordDatabaseSettings.Value.DatabaseName);

            if (resetPasswordDatabaseSettings.Value.ResetPasswordCollectionName is not null)
            {
                _Collection = mongoDatabase.GetCollection<ResetPassword>(resetPasswordDatabaseSettings.Value.ResetPasswordCollectionName);
            }

            this.mailService = mailService;
            this.jwtSettings = jwtSettings;
            configuration = iConfig;
            EnvirnmentVariable = "DevSetting";
        }

        public async Task RemoveAsync(string id) =>
            await _Collection.DeleteOneAsync(x => x.Id == id);

        public async Task RemoveByEmailAsync(string email) =>
            await _Collection.DeleteManyAsync(x => x.Email == email);

        public async Task<UserTokens?> GenerateTokenForResetPassword(User valid, string orgid = "")
        {
            bool tokenNotGenerated = true;

            do
            {
                var token = JwtHelpers.GenResetPasswordTokenkey(new UserTokens()
                {
                    EmailId = valid.Email,
                    GuidId = Guid.NewGuid(),
                    Id = valid.Id,
                    UserName = valid.Email,
                    OrganizationId = orgid,
                }, jwtSettings);

                var validToken = await GetValidResetPasswordFromToken(token.Token);

                if (validToken is null)
                {
                    tokenNotGenerated = false;
                    return token;
                }

            } while (tokenNotGenerated);
            return null;
        }

        public async Task<ResetPassword?> GetValidResetPasswordFromToken(string token)
        {
            var resetPassword = await _Collection.Find(x => x.Token == token).FirstOrDefaultAsync();

            if (resetPassword is not null
                && resetPassword.TokenValideTill > DateTime.Now)
            {
                return resetPassword;
            }
            else
            {
                return null;
            }
        }

        public async Task<ResetPassword?> GetValidVerifyLinkFromToken(string token)
        {
            var resetPassword = await _Collection.Find(x => x.Token == token).FirstOrDefaultAsync();

            if (resetPassword is not null)
            {
                return resetPassword;
            }
            else
            {
                return null;
            }
        }

        public async Task SendMail(UserTokens token, EmailType emailType, bool canVerifyUser = false, string userName = "")
        {
            var resetPassword = new ResetPassword
            {
                Token = token.Token,
                TokenCreatedAt = DateTime.Now,
                TokenValideTill = token.ExpiredTime,
                Email = token.UserName,
                OrganizationId = token.OrganizationId,
                CanVerifyUser = canVerifyUser
            };

            await CreateAsync(resetPassword);

            var subject = emailType switch
            {
                EmailType.ResetPasswordEmail => "Resolve Engine: Reset your password",
                EmailType.CreatePasswordEmail => "Resolve Engine: Create your password",
                EmailType.VerifyEmail => "Resolve Engine: Verify your Email",
                _ => "",
            };

            var baseUrl = configuration.GetValue<string>(String.Format("{0}:BaseUrl", EnvirnmentVariable));
            var body = string.Empty;
            var webRequestUrl = "";
            webRequestUrl = emailType switch
            {
                EmailType.ResetPasswordEmail => string.Format("{0}/Content/HTML/ResetPasswordEmailTemplate.html", baseUrl),
                EmailType.CreatePasswordEmail => string.Format("{0}/Content/HTML/CreatePasswordEmailTemplate.html", baseUrl),
                EmailType.VerifyEmail => string.Format("{0}/Content/HTML/VerifyEmailTemplate.html", baseUrl),
                _ => "",
            };

            var webRequest = System.Net.WebRequest.Create(webRequestUrl);
            using (var response = webRequest.GetResponse())
            using (var content = response.GetResponseStream())
            using (var reader = new StreamReader(content))
            {
                body = reader.ReadToEnd();
            }

            var url = emailType switch
            {
                EmailType.ResetPasswordEmail => configuration.GetValue<string>(String.Format("{0}:ResetPasswordEmailURL", EnvirnmentVariable)),
                EmailType.VerifyEmail => configuration.GetValue<string>(String.Format("{0}:VerifyEmailURL", EnvirnmentVariable)),
                EmailType.CreatePasswordEmail => configuration.GetValue<string>(String.Format("{0}:ResetPasswordEmailURL", EnvirnmentVariable)),
                _ => "",
            };

            var builder = new Stubble.Core.Builders.StubbleBuilder();
            var boundTemplate = builder.Build().Render(body, new
            {
                APIUrlLink = String.Format("{0}/{1}", url, token.Token),
                BaseUrl = baseUrl,
                UserName = userName
            });

            var request = new MailRequest
            {
                ToEmail = token.UserName,
                Subject = subject,
                Body = boundTemplate.ToString()
            };

            await mailService.SendEmailAsync(request);
        }
    }

}
