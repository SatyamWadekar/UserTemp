using Amazon;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using UserTemp.Helper;
using UserTemp.JWT;
using UserTemp.Model;
using UserTemp.Services;

namespace UserTemp.Controllers
{
    [ApiController]
    [Route("api/v1/user")]
    public class UserController : Controller
    {
        private readonly UserService _userService;
        private readonly ILogger<UserController> _logger;
        private readonly JwtSettings jwtSettings;
        private readonly IConfiguration configuration;
        private readonly string EnvirnmentVariable;
        private readonly string AccessKey;
        private readonly string SecretAccessKey;
        private readonly string BucketName;
        private readonly AWSHelper AWSHelper;

        public UserController(UserService userService, ILogger<UserController> logger, JwtSettings jwtSettings, IConfiguration configuration)
        {
            _userService = userService;
            _logger = logger;
            this.jwtSettings = jwtSettings;
            EnvirnmentVariable = "DevSetting";
            this.configuration = configuration;

            AccessKey = Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID") != null ? Environment.GetEnvironmentVariable("AWS_ACCESS_KEY_ID").ToString() : string.Empty;
            SecretAccessKey = Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY") != null ? Environment.GetEnvironmentVariable("AWS_SECRET_ACCESS_KEY").ToString() : string.Empty; ;
            BucketName = configuration.GetValue<string>(String.Format("{0}:BucketName", EnvirnmentVariable));

            AWSHelper = new AWSHelper(AccessKey, SecretAccessKey, BucketName, RegionEndpoint.APSouth1);
        }

        [HttpGet("{orgId:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Get(string orgId)
        {
            try
            {
                var user = await _userService.GetVerifiedUserByOrgIdAsync(orgId);

                var org = await _userService.GetOrgById(orgId);

                if (user is null || user.Count <= 0 || org is null)
                {
                    return NotFound(new { error = "Users not found" });
                }

                return Ok(new
                {
                    value = user.Select(x => new
                    {
                        userId = x.Id,
                        user = x,
                        userImageUrl = AWSHelper.GetImage(x.ProfileImage),
                        isOrganizationOwner = x.Id == org.OrganizationOwner,
                    })
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpGet]
        [Route("invitedusers/{orgId:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> GetInvitedUser(string orgId)
        {
            try
            {
                var user = await _userService.GetNotVerifiedUserByOrgIdAsync(orgId);

                if (user is null || user.Count <= 0)
                {
                    return NotFound(new { error = "Users not found" });
                }

                return Ok(new
                {
                    value = user.Select(x => new
                    {
                        userId = x.Id,
                        user = x,
                        verificationStatus = "Pending"
                    })
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpGet("{id:length(24)}/{orgId:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Get(string id, string orgId)
        {
            var user = await _userService.GetByOrgIdAsync(id, orgId);

            var org = await _userService.GetOrgById(orgId);

            if (user is null || org is null)
            {
                return NotFound(new { error = "Users not found" });
            }

            return Ok(new
            {
                value = new
                {
                    userId = user.Id,
                    user = user,
                    userImageUrl = AWSHelper.GetImage(user.ProfileImage),
                    isOrganizationOwner = user.Id == org.OrganizationOwner,
                }
            });
        }

        [HttpGet("getCurrentUser")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> GetCurrentUser()
        {
            var user = await _userService.GetUserByToken(Request);

            if (user is null)
            {
                return NotFound(new { error = "Users not found" });
            }

            return Ok(new
            {
                value = new
                {
                    userId = user.Id,
                    user = user,
                    userImageUrl = AWSHelper.GetImage(user.ProfileImage),
                }
            });
        }

        [HttpPost]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Post(User newUser)
        {
            if (newUser is not null)
            {
                var validEmail = await _userService.ValidateEmail(newUser.Email);
                if (validEmail is null)
                {
                    await _userService.CreateUser(newUser);
                }
                else
                {
                    return Conflict(new { error = "Email already exists" });
                }

            }
            else
            {
                return NotFound(new { error = "Users can not be empty" });
            }

            return Ok(new { value = "User created successfully" });
        }

        [HttpPost]
        [Route("createuser")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> CreateUser(AddUser newUser)
        {
            if (newUser is not null)
            {
                var user = await _userService.GetUserByToken(Request);

                if (user is not null && user.Id is not null)
                {
                    var validEmail = await _userService.ValidateEmail(newUser.Email);
                    if (validEmail is null)
                    {
                        await _userService.CreateUser(newUser, user.Id);

                        return Ok(new { value = "User created successfully" });
                    }
                    else
                    {
                        if (!validEmail.Organization.ContainsKey(newUser.OrganizationId))
                        {
                            await _userService.AddExistingUser(newUser, user.Id);

                            return Ok(new { error = "User created successfully" });
                        }
                        else
                        {
                            return Conflict(new { error = "Email already exists in this organization" });
                        }

                    }
                }
                else
                {
                    return NotFound(new { error = "User not found from token" });
                }

            }
            else
            {
                return NotFound(new { error = "Users not found" });
            }

        }

        [HttpPut("{id:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Update(string id, User updatedUser)
        {
            var user = await _userService.GetAsync(id);

            if (user is null)
            {
                return NotFound(new { error = "Users not found" });
            }

            updatedUser.Id = user.Id;
            updatedUser.Organization = user.Organization;
            updatedUser.IsOrganizationOwner = user.IsOrganizationOwner;

            await _userService.UpdateAsync(id, updatedUser);

            return Ok(new { value = "User updated successfully" });
        }

        [HttpPatch("{id:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> PatchUser(string id, string orgId)
        {
            var currentUser = await _userService.GetUserByToken(Request);

            var user = await _userService.GetAsync(id);

            if (user is null || currentUser is null)
            {
                return NotFound(new { error = "Users not found" });
            }

            var stream = new StreamReader(Request.Body);
            var updateUserJson = await stream.ReadToEndAsync();
            var updateUserJObject = JObject.Parse(updateUserJson);

            var updatedUser = JsonConvert.DeserializeObject<User>(updateUserJson);

            var isUpdate = Commonhelper.PathchObject(updateUserJObject, user);

            if (updatedUser is not null)
            {
                if (updateUserJObject[nameof(updatedUser.IsOrganizationOwner)] is not null && updatedUser.IsOrganizationOwner != user.IsOrganizationOwner)
                {
                    if (currentUser.Id != user.Id)
                    {
                        await _userService.UpdateUserOrgAsync(currentUser, orgId, id);
                    }
                    else
                    {
                        return BadRequest(new { error = "Your ownership can not be removed" });
                    }
                }

            }

            if (isUpdate)
            {
                await _userService.UpdateAsync(id, user);
            }

            return Ok(new { value = "User updated successfully" });
        }

        [HttpPut]
        [Route("me")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> UpdateCurrentUser(User updatedUser)
        {
            var user = await _userService.GetUserByToken(Request);

            if (user is not null)
            {
                updatedUser.Id = user.Id;
                updatedUser.Organization = user.Organization;
                updatedUser.IsOrganizationOwner = user.IsOrganizationOwner;

                if (user.Id is not null)
                {
                    await _userService.UpdateAsync(user.Id, updatedUser);

                }
            }

            return Ok(new { value = "User updated successfully" });
        }


        [HttpPatch]
        [Route("me")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> PatchCurrentUser()
        {
            var user = await _userService.GetUserByToken(Request);

            var stream = new StreamReader(Request.Body);
            var updateJson = await stream.ReadToEndAsync();
            var updateJObject = JObject.Parse(updateJson);

            if (user is not null)
            {
                var isUpdate = Commonhelper.PathchObject(updateJObject, user);

                if (user.Id is not null && isUpdate)
                {
                    await _userService.UpdateAsync(user.Id, user);
                }
            }

            return Ok(new { value = "User updated successfully" });
        }

        [HttpDelete("{id:length(24)}")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> Delete(string id)
        {
            var user = await _userService.GetAsync(id);

            if (user is null)
            {
                return NotFound(new { error = "Users not found" });
            }

            await _userService.RemoveAsync(id);

            return Ok(new { value = "User deleted successfully" });
        }

        [HttpPut]
        [Route("mfa")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> UpdateMFA(MultiFactorAuthentication mfa)
        {
            var user = await _userService.GetUserByToken(Request);

            if (user is not null && user.Id is not null)
            {
                await _userService.UpdateMFAAsync(user.Id, mfa);
            }

            return Ok(new { value = "Multi factor authentication added successfully" });
        }

        [HttpDelete]
        [Route("removemfa")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> RemoveMFA()
        {
            var user = await _userService.GetUserByToken(Request);
            if (user is not null)
            {
                user.MultiFactorAuthentication = new MultiFactorAuthentication();
                user.IsMultiFactorAuthentication = false;

                if (user.Id is not null)
                {
                    await _userService.UpdateAsync(user.Id, user);
                }

            }
            else
            {
                return NotFound(new { error = "User not found" });
            }

            return Ok(new { value = "Multi factor authentication added successfully" });
        }


        [HttpPut]
        [Route("changepassword")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> ChangePassword(ChangePassword changePassword)
        {
            var user = await _userService.GetUserByToken(Request);
            if (user is not null
                && !String.IsNullOrWhiteSpace(changePassword.CurrentPassword)
                && !String.IsNullOrWhiteSpace(changePassword.NewPassword)
                && !String.IsNullOrWhiteSpace(changePassword.ConfirmPassword)
                && changePassword.NewPassword == changePassword.ConfirmPassword)
            {
                changePassword.Email = user.Email;

                await _userService.ChangePassword(changePassword);

                return Ok(new { value = "Password changed successfully" });
            }
            else
            {
                return BadRequest(new { error = "Some error occured while changing password" });
            }
        }

        [HttpPut]
        [Route("removeinvitation")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> RemoveInvitation(RemoveInvitation removeInvitation)
        {
            try
            {
                var validEmail = await _userService.ValidateNotVerifiedEmail(removeInvitation.Email);

                if (validEmail is not null && removeInvitation.OrganizationId is not null)
                {
                    await _userService.RemoveInvitation(validEmail, removeInvitation.OrganizationId);

                    return Ok(new { value = "User invitation hasa been removed" });

                }
                else
                {
                    return NotFound(new { error = "Email not found" });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new
                {
                    error = "Error occured while removing invitation",
                    exception = ex.Message
                });
            }
        }

        [HttpPut]
        [Route("updateimage")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<ActionResult> UploadImage(IFormFile image)
        {
            var user = await _userService.GetUserByToken(Request);

            if (user is not null)
            {
                if (image is not null)
                {
                    var fileName = String.Format("{0}_{1}", user.Id, image.FileName);

                    await AWSHelper.UploadImage(image, fileName);

                    user.ProfileImage = fileName;

                    if (user.Id is not null)
                    {
                        await _userService.UpdateAsync(user.Id, user);

                        return Ok(new { value = "User image updated successfully" });
                    }
                    else
                    {
                        return NotFound(new { error = "User not found" });
                    }

                }
                else
                {
                    return NotFound(new { error = "Image not found" });
                }
            }
            else
            {
                return NotFound(new { error = "User not found" });
            }

        }

    }
}
