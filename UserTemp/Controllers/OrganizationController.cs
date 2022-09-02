using Amazon;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using UserTemp.Helper;
using UserTemp.JWT;
using UserTemp.Model;
using UserTemp.Services;

namespace UserTemp.Controllers
{
    [ApiController]
    [Route("api/v1/organizations")]
    public class OrganizationsController : Controller
    {
        private readonly OrganizationService _organizationService;
        private readonly UserService _userService;
        private readonly JwtSettings jwtSettings;
        private readonly ILogger<OrganizationsController> _logger;
        private readonly IConfiguration configuration;
        private readonly string EnvirnmentVariable;
        private readonly string AccessKey;
        private readonly string SecretAccessKey;
        private readonly string BucketName;
        private readonly AWSHelper AWSHelper;

        public OrganizationsController(OrganizationService organizationService, ILogger<OrganizationsController> logger, JwtSettings jwtSettings, UserService userService, IConfiguration configuration)
        {
            _organizationService = organizationService;
            _userService = userService;
            this.jwtSettings = jwtSettings;
            _logger = logger;
            EnvirnmentVariable = "DevSetting";
            this.configuration = configuration;

            AccessKey = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID") != null ? Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID").ToString() : string.Empty;
            SecretAccessKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY") != null ? Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY").ToString() : string.Empty; ;
            BucketName = configuration.GetValue<string>(String.Format("{0}:BucketName", EnvirnmentVariable));

            AWSHelper = new AWSHelper(AccessKey, SecretAccessKey, BucketName, RegionEndpoint.APSouth1);
        }

        [HttpGet]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Get()
        {
            var user = await GetUserByToken();

            if (user is not null && user.Id is not null)
            {
                var org = await _organizationService.GetAsync(user.Id);

                if (org is null || org.Count <= 0)
                {
                    return Ok();
                }

                return Ok(new
                {
                    value =
                    org.Select(x => new
                    {
                        OrganizationId = x.Id,
                        Organization = x,
                        organizationLogoUrl = AWSHelper.GetImage(x.Logo)
                    })
                });

            }
            else
            {
                return NotFound(new { error = "User not found" });
            }

        }

        [HttpGet("{organizationId:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Get(string organizationId)
        {
            var user = await GetUserByToken();

            if (user is not null && user.Id is not null)
            {
                var organization = await _organizationService.GetAsync(organizationId, user.Id);

                if (organization is null)
                {
                    return NotFound(new { error = "Organizations not found" });
                }

                return Ok(new
                {
                    value = new
                    {
                        organizationId = organization.Id,
                        organization = organization,
                        organizationLogoUrl = AWSHelper.GetImage(organization.Logo)
                    }
                });

            }
            else
            {
                return NotFound(new { error = "User not found" });
            }

        }

        [HttpPost]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Post(string createOrganizationname)
        {

            try
            {
                if (!String.IsNullOrWhiteSpace(createOrganizationname))
                {

                    var user = await GetUserByToken();

                    if (user is not null && user.Id is not null)
                    {
                        var newOrganization = new Organization
                        {
                            Name = createOrganizationname,
                            OrganizationMembers = new List<string?>
                                {
                                    user.Id
                                },
                            OrganizationOwner = user.Id
                        };
                        await _organizationService.CreateAsync(newOrganization);

                        user.IsOrganizationOwner = true;
                        if (newOrganization.Id is not null)
                        {
                            user.Organization.Add(newOrganization.Id, true);
                        }

                        if (user.Id is not null)
                        {
                            await _userService.UpdateAsync(user.Id, user);
                        }

                        return Ok(new { value = "Organization created successfully" });
                    }
                    else
                    {
                        return NotFound(new { error = "User not found" });
                    }
                }
                else
                {
                    return BadRequest(new { error = "Failed to create organization" });

                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "Some exception occured while processing", exception = ex });
            }

        }

        [HttpPut("{organizationId:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Update(string organizationId, Organization updatedOrganization)
        {
            var user = await GetUserByToken();

            if (user is not null && user.Id is not null)
            {
                var organization = await _organizationService.GetAsync(organizationId, user.Id);

                if (organization is null || organization.OrganizationOwner != user.Id)
                {
                    return NotFound(new { error = "Organization or user not found" });
                }

                updatedOrganization.Id = organization.Id;
                updatedOrganization.OrganizationOwner = organization.OrganizationOwner;
                updatedOrganization.OrganizationMembers = organization.OrganizationMembers;

                await _organizationService.UpdateAsync(organizationId, updatedOrganization);

                return Ok(new { value = "Organization updated successfully" });
            }
            else
            {
                return NotFound(new { error = "User not found" });
            }

        }

        [HttpPatch("{organizationId:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Patch(string organizationId)
        {
            var user = await GetUserByToken();

            if (user is not null && user.Id is not null)
            {
                var organization = await _organizationService.GetAsync(organizationId, user.Id);

                if (organization is null || organization.OrganizationOwner != user.Id)
                {
                    return NotFound(new { error = "Organization or user not found" });
                }

                var stream = new StreamReader(Request.Body);
                var updateJson = await stream.ReadToEndAsync();
                var updateJObject = JObject.Parse(updateJson);

                var isUpdate = Commonhelper.PathchObject(updateJObject, organization);

                if (isUpdate)
                {
                    await _organizationService.UpdateAsync(organizationId, organization);
                }

                return Ok(new { value = "Organization updated successfully" });
            }
            else
            {
                return NotFound(new { error = "User not found" });
            }

        }

        [HttpPut("{organizationId:length(24)}/uploadImage")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> UploadFileToS3(string organizationId, IFormFile file)
        {
            try
            {
                var fileName = String.Format("{0}_{1}", organizationId, file.FileName);

                Console.WriteLine("Started with uploading image");
                await AWSHelper.UploadImage(file, fileName);

                //use this for image getting
                //https://docs.aws.amazon.com/sdkfornet/latest/apidocs/items/MS3S3GetPreSignedURLGetPreSignedUrlRequestNET45.html

                var organization = await _organizationService.GetOrg(organizationId);
                organization.Logo = fileName;
                await _organizationService.UpdateAsync(organizationId, organization);

                return Ok(new { value = "Image uploaded successfully" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "Some error occured while uploading image", exception = ex.HelpLink });
            }
        }

        [HttpDelete("{organizationId}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Delete(string organizationId, string organizationName)
        {
            var user = await GetUserByToken();

            if (user is not null && user.Id is not null)
            {
                var organization = await _organizationService.GetAsync(organizationId, user.Id);

                if (organization is null || organization.OrganizationOwner != user.Id || organizationName != organization.Name)
                {
                    return NotFound(new { error = "Organization or user not found" });
                }

                organization.IsActive = false;

                if (organization.Id is not null)
                {
                    await _organizationService.UpdateAsync(organization.Id, organization);
                }

                return Ok(new { value = "Organization deleted successfully" });

            }
            else
            {
                return NotFound(new { error = "User not found" });
            }

        }

        [HttpGet]
        [Route("GetTokenFromRequest")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public string GetTokenFromRequest()
        {
            var token = Request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value;

            var tempToken = token.ToString();

            token = tempToken.Split(' ').LastOrDefault();

            return token;
        }

        [HttpGet]
        [Route("GetTokenByUser")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<User?> GetUserByToken()
        {
            var token = GetTokenFromRequest();

            if (token is not null)
            {
                var principal = JwtHelpers.GetPrincipalFromExpiredToken(token, jwtSettings);
                if (principal is not null
                    && principal.Identity is not null
                    && principal.Identity.Name is not null)
                {
                    var email = principal.Identity.Name;
                    var user = await _userService.GetByEmailAsync(email);
                    if (user is not null)
                    {
                        return user;
                    }

                }
            }

            return null;
        }

    }
}
