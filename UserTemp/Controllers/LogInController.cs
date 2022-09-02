using Microsoft.AspNetCore.Mvc;
using UserTemp.Data.Enums;
using UserTemp.JWT;
using UserTemp.Model;
using UserTemp.Model.Enums;
using UserTemp.Services;

namespace UserTemp.Controllers
{
    public class LogInController : Controller
    {
        private readonly UserService _userService;
        private readonly ResetPasswordService _resetPasswordService;
        private readonly JwtSettings jwtSettings;
        private readonly IConfiguration configuration;
        private readonly string EnvirnmentVariable;

        public LogInController(UserService userService, JwtSettings jwtSettings, ResetPasswordService resetPasswordService, IConfiguration iConfig)
        {
            _userService = userService;
            _resetPasswordService = resetPasswordService;
            this.jwtSettings = jwtSettings;
            configuration = iConfig;
            EnvirnmentVariable = "DevSetting";
        }

        [HttpPost]
        [Route("gettoken")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult GetToken(LogInUser userLogins)
        {
            try
            {
                if (_userService.ValidEmailString(userLogins.Email) && _userService.ValidPasswordString(userLogins.Password))
                {
                    var token = GenerateToken(userLogins);

                    if (token is not null)
                    {
                        return Ok(new { value = token });
                    }
                    else
                    {
                        return BadRequest(new { error = "wrong password" });
                    }
                }
                else
                {
                    return BadRequest(new { error = "Please check email or password" });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { exception = String.Format("Exception occured : {0}", ex) });
            }
        }

        [HttpPost]
        [Route("refreshtoken")]
        public IActionResult RefreshToken(TokenApiModel tokenApiModel)
        {
            try
            {
                if (tokenApiModel is null || tokenApiModel.AccessToken is null)
                {
                    return BadRequest(new { error = "Invalid client request" });
                }
                string accessToken = tokenApiModel.AccessToken;
                string refreshToken = tokenApiModel.RefreshToken;
                var principal = JwtHelpers.GetPrincipalFromExpiredToken(accessToken, jwtSettings);
                var email = principal.Identity.Name; //this is mapped to the Name claim by default
                var user = _userService.GetUserByEmail(email);
                if (user is null || user.RefreshToken != refreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
                {
                    return NotFound(new { error = "User token not found" });
                }
                var logInUser = new LogInUser { Email = user.Email, Password = user.Password };
                var token = GenerateToken(logInUser);
                if (token != null)
                {
                    return Ok(new
                    {
                        token = token.Token,
                        refreshToken = token.RefreshToken
                    });
                }
                else
                {
                    return BadRequest(new { error = "Token not generated" });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { exception = String.Format("Exception occured : {0}", ex) });
            }
        }

        /// <summary>
        /// Creating user in system
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("register")]
        public async Task<ActionResult> Register(RegisterUser registerUser)
        {
            if (registerUser is not null)
            {
                if (_userService.ValidEmailString(registerUser.Email) && _userService.ValidPasswordString(registerUser.Password) && !String.IsNullOrWhiteSpace(registerUser.Name))
                {
                    var isEmailExists = await _userService.IsEmailValid(registerUser.Email);

                    if (isEmailExists is not null && isEmailExists == false)
                    {
                        var user = new User
                        {
                            fullName = registerUser.Name,
                            Email = registerUser.Email,
                            Password = Masking.GetEncryptedString(registerUser.Password, configuration.GetValue<string>(String.Format("{0}:salt", EnvirnmentVariable))),
                            Role = EnvironmentEnum.Production,
                            IsVerified = false
                        };
                        await _userService.CreateUser(user);

                        var validEmail = await _userService.ValidateEmail(registerUser.Email);

                        if (validEmail is not null)
                        {
                            var token = await _resetPasswordService.GenerateTokenForResetPassword(validEmail);
                            if (token is not null)
                            {
                                await _resetPasswordService.SendMail(token, EmailType.VerifyEmail, true, registerUser.Name);
                            }
                        }
                        else
                        {
                            return BadRequest(new { error = "Error occured while sending verification mail" });
                        }
                    }
                    else
                    {
                        return Conflict(new { error = "Email already exists" });
                    }

                }
                else
                {
                    return BadRequest(new { error = "Please enter valid inputs" });
                }
            }
            else
            {
                return NotFound(new { error = "Users can not be empty" });
            }

            return Ok(new { value = "Verification link sent successfully" });
        }

        /// <summary>
        /// Login to system, for valid user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("login")]
        public async Task<ActionResult> LogIn(LogInUser user)
        {
            if (_userService.ValidEmailString(user.Email) && _userService.ValidPasswordString(user.Password))
            {
                var result = await _userService.LogIn(user);

                if (!String.IsNullOrWhiteSpace(result.Id))
                {
                    var logInUser =
                        new LogInUser
                        {
                            Email = user.Email,
                            Password = Masking.GetEncryptedString(user.Password, configuration.GetValue<string>(String.Format("{0}:salt", EnvirnmentVariable)))

                        };
                    var token = GenerateToken(logInUser);
                    if (token != null)
                    {
                        return Ok(new
                        {
                            value = new
                            {
                                token = token.Token,
                                refreshToken = token.RefreshToken
                            }
                        });
                    }
                    else
                    {
                        return BadRequest(new { error = "Token not generated" });
                    }

                }
                return BadRequest(new { error = "Please check email or password" });
            }
            else
            {
                return BadRequest(new { error = "Please check email or password" });
            }

        }

        /// <summary>
        /// Logging out the current user which is logged in
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("logout")]
        public async Task<ActionResult> LogOut()
        {
            var token = GetTokenByRequest();

            if (token is not null)
            {
                var principal = JwtHelpers.GetPrincipalFromExpiredToken(token, jwtSettings);
                if (principal is not null
                    && principal.Identity is not null
                    && principal.Identity.Name is not null)
                {
                    var email = principal.Identity.Name;
                    var user = new User();
                    if (email is not null)
                    {
                        user = _userService.GetUserByEmail(email);
                        if (user is not null)
                        {
                            user.RefreshToken = String.Empty;
                            user.RefreshTokenExpiryTime = null;
                            if (user.Id is not null)
                            {
                                await _userService.UpdateAsync(user.Id, user);

                            }
                        }

                    }

                }
                else
                {
                    return BadRequest(new { error = "Some error occured while fetching token" });
                }

            }
            else
            {
                return NotFound(new { error = "Token not found" });
            }

            return Ok(new { value = "Logged out successfully" });
        }

        /// <summary>
        /// Sending the reset password link to user if exists
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("forgotpassword/{email}")]
        public async Task<ActionResult> SendResetPasswordLink(string email)
        {
            try
            {
                var valid = await _userService.ValidateEmail(email);
                if (valid is not null)
                {
                    var token = await _resetPasswordService.GenerateTokenForResetPassword(valid);

                    if (token is not null)
                    {
                        await _resetPasswordService.SendMail(token, EmailType.ResetPasswordEmail, userName: valid.fullName);

                        return Ok(new { value = "Password reset link generated" });

                    }
                    else
                    {
                        return BadRequest(new { error = "Token not generated" });
                    }

                }
                else
                {
                    return NotFound(new { error = "Please enter valid email" });
                }


            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "Exception occured while generating forgot password link", exception = ex });
            }

        }

        [HttpPost]
        [Route("resetpassword")]
        public async Task<ActionResult> ResetPassword(ResetPassword newPassword)
        {
            try
            {
                if (_userService.ValidPasswordString(newPassword.NewPassword)
                    && _userService.ValidPasswordString(newPassword.ConfirmPassword))
                {
                    if (newPassword.NewPassword == newPassword.ConfirmPassword && newPassword.Token is not null)
                    {
                        var validToken = await _resetPasswordService.GetValidResetPasswordFromToken(newPassword.Token);

                        if (validToken is not null)
                        {
                            var email = validToken.Email;
                            if (email is not null)
                            {
                                var resetPassword = new ChangePassword
                                {
                                    Email = email,
                                    NewPassword = newPassword.NewPassword
                                };
                                await _userService.ResetPassword(resetPassword, validToken.OrganizationId, validToken.CanVerifyUser);

                                if (validToken.Id is not null)
                                {
                                    await _resetPasswordService.RemoveAsync(validToken.Id);
                                }

                                return Ok(new { value = "Password has been changed" });

                            }
                            else
                            {
                                return BadRequest(new { error = "Some error occured, please contact administrator" });
                            }

                        }
                        else
                        {
                            return NotFound(new { error = "Some error occured while fetching token" });
                        }

                    }
                    else
                    {
                        return Conflict(new { error = "New password and confirm password are not matching" });
                    }
                }
                else
                {
                    return BadRequest(new { error = "Please enter valid inputs" });
                }

            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "Exception occured while resetting password", exception = ex });

            }
        }

        [HttpPost]
        [Route("verifyemail/{token}")]
        public async Task<ActionResult> VerifyEMail(string token)
        {
            try
            {
                if (token is not null)
                {
                    var validToken = await _resetPasswordService.GetValidVerifyLinkFromToken(token);

                    if (validToken is not null)
                    {
                        var email = validToken.Email;
                        if (email is not null)
                        {
                            var resetPassword = new ChangePassword
                            {
                                Email = email
                            };
                            await _userService.ResetPassword(resetPassword, validToken.OrganizationId, validToken.CanVerifyUser);

                            if (validToken.Id is not null)
                            {
                                await _resetPasswordService.RemoveAsync(validToken.Id);
                            }

                            return Ok(new { value = "Email has been verified" });

                        }
                        else
                        {
                            return BadRequest(new { error = "Some error occured, please contact administrator" });
                        }

                    }
                    else
                    {
                        return NotFound(new { error = "Some error occured while fetching token" });
                    }

                }
                else
                {
                    return NotFound(new { error = "Token can not be empty" });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "Exception occured while resetting password", exception = ex });

            }
        }


        [HttpPost]
        [Route("validatemailtoken")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<ActionResult> ValidatEmailToken(string token)
        {
            try
            {
                if (token is not null && !String.IsNullOrWhiteSpace(token))
                {
                    var validToken = await _resetPasswordService.GetValidVerifyLinkFromToken(token);

                    if (validToken is not null)
                    {
                        return Ok(new { value = "Token is valid" });

                    }
                    else
                    {
                        return NotFound(new { error = "Some error occured while fetching token" });
                    }
                }
                else
                {
                    return NotFound(new { error = "Token can not be empty" });
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { error = "Exception occured while fetching token", exception = ex });

            }
        }


        [HttpPost]
        [Route("generatetoken")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public UserTokens? GenerateToken(LogInUser userLogins)
        {
            var token = new UserTokens();
            var user = new User
            {
                Email = userLogins.Email,
                Password = userLogins.Password,
            };
            var Valid = _userService.ValidateEmailAndPassword(user);
            if (Valid is not null)
            {
                user = _userService.GetByEmailAsync(user.Email).Result;
                token = JwtHelpers.GenTokenkey(new UserTokens()
                {
                    EmailId = user.Email,
                    GuidId = Guid.NewGuid(),
                    Id = user.Id,
                    UserName = user.Email,
                }, jwtSettings);
                var refreshToken = JwtHelpers.GenerateRefreshToken();
                user.RefreshToken = refreshToken;
                var refreshTokenExpiryTime = DateTime.UtcNow.AddDays(1);
                user.RefreshTokenExpiryTime = refreshTokenExpiryTime;
                var tempResult = _userService.UpdateAsync(user.Id, user);
                token.RefreshToken = refreshToken;
                token.RefreshTokenExpiryTime = refreshTokenExpiryTime;
            }
            else
            {
                token = null;
            }
            return token;
        }

        [HttpGet]
        [Route("gettokenfromrequest")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public string GetTokenByRequest()
        {
            var token = Request.Headers.FirstOrDefault(x => x.Key == "Authorization").Value;

            var tempToken = token.ToString();
            token = tempToken.Split(' ').LastOrDefault();

            return token;
        }

    }
}
