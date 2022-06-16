
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Northwind.Security.Areas.Identity.Data;
using Northwind.Security.Areas.Identity.Services;
using Northwind.Security.Authentication.JwtFeatures;
using Northwind.Security.Models;
using System.Threading.Tasks;

namespace Northwind.WebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly JwtHandler _jwtHandler;
        private readonly IAuthenticationService _authenticationService;

        public AuthenticateController(UserManager<ApplicationUser> userManager
            , IConfiguration configuration
            , JwtHandler jwtHandler
            , IAuthenticationService authenticationService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _jwtHandler = jwtHandler;
            _authenticationService = authenticationService;
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var applicationUser = await _userManager.FindByNameAsync(loginModel.Username);

            if (applicationUser is not null)
            {
                var result = await _userManager.CheckPasswordAsync(applicationUser, loginModel.Password);

                if (result)
                {
                    var token = _jwtHandler.GenerateToken();

                    return Ok(new { token = token });
                }

                return BadRequest("Please provide the correct Username and Password");
            }

            return NoContent();
        }

        [HttpPost]


        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel registerModel)
        {
            var applicationUser = await _userManager.FindByNameAsync(registerModel.Username);

            if (applicationUser is null)
            {
                var result = await _authenticationService.Register(registerModel);

                if (result.IsSuccessful)
                {
                    return Ok("Account registered succesfully");
                }

                return BadRequest(result.Message);
            }

            return Conflict("The Employee email already exists");

        }


        [HttpPost("activateaccount")]
        public async Task<IActionResult> ActivateAccount([FromBody] ActivateAccountModel activateAccountModel)
        {
            if(activateAccountModel.Password != activateAccountModel.ConfirmPassword)
            {
                return BadRequest("Please ensure that the Password and Password Confirmation are the same");
            }

            var result = await _authenticationService.ActivateAccount(activateAccountModel);

            if (result.IsSuccessful)
            {
                return Ok(result.Message);
            }

            return BadRequest(result.Message);
        }


        [HttpPost]
        [Route("changepassword")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordModel changePasswordModel)
        {
            var applicationUser = await _userManager.FindByEmailAsync(changePasswordModel.Username);

            if (applicationUser is null)
            {
                return NotFound("User does not exist");
            }

            var result = await _userManager.ChangePasswordAsync(applicationUser
                , changePasswordModel.CurrentPassword
                , changePasswordModel.NewPassword);

            if (result.Succeeded)
            {
                return Ok("Password Changed Succesfully");
            }

            return BadRequest("Password change failed! Please check old password and try again.");
        }

        [HttpPost]
        [Route("recoverpassword")]
        public async Task<IActionResult> RecoverPassword([FromBody] ForgotPasswordModel forgotPasswordModel)
        {
            var applicationUser = await _userManager.FindByEmailAsync(forgotPasswordModel.Username);

            if (applicationUser is null)
            {
                return NoContent();
            }

            var result = await _authenticationService.SendPasswordRecoveryLink(applicationUser);

            if (result.IsSuccessful)
            {
                return Ok("A password reset link has been sent to users email address.");
            }

            return BadRequest(result.Message);
        }

        [HttpPost]
        [Route("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel resetPasswordModel)
        {

            if (resetPasswordModel.NewPassword != resetPasswordModel.ConfirmNewPassword)
            {
                return BadRequest("Your new passwords do not match");
            }

            var result = await _authenticationService.ResetPassword(resetPasswordModel);

            if (result.IsSuccessful)
            {
                return Ok("Password reset successful");
            }

            return BadRequest(result.Message);
        }
    }
}
