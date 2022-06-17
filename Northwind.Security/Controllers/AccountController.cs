
using AutoMapper;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;
using Northwind.DataModels.Authentication;
using Northwind.Portal.Models;
using Northwind.Security.Areas.Identity.Data;
using Northwind.Security.Areas.Identity.Services;
using Northwind.Security.Authentication.JwtFeatures;
using Northwind.Security.Models;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Northwind.Security.Controllers
{
    public class AccountController : BaseController
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;
        private readonly JwtHandler _jwtHandler;
        private readonly IAuthenticationService _authenticationService;

        public AccountController(UserManager<ApplicationUser> userManager
            , SignInManager<ApplicationUser> signInManager
            , IConfiguration configuration
            , JwtHandler jwtHandler
            , IAuthenticationService authenticationService
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _jwtHandler = jwtHandler;
            _authenticationService = authenticationService;
        }

        public IActionResult RegisterUser()
        {
            RegisterModel registerModel = new();

            return View(registerModel);
        }

        [Authorize]
        [HttpPost("RegisterUser")]
        public async Task<IActionResult> RegisterUser(RegisterModel registerModel)
        {
            if (ModelState.IsValid)
            {
                var result = await _authenticationService.Register(registerModel);

                if (result.IsSuccessful)
                {
                    NotifyUser("User Added Successfully", "User Added", NotificationType.success);

                    return Redirect("/Account/Users");
                }

                ModelState.AddModelError("error", result.Message);

                return View(registerModel);
            }

            return View(registerModel);
        }

        public IActionResult Login([FromQuery] string response_type
            ,string client_id
            ,string redirect_uri
            ,string scope
            ,string state)
        {
            LoginModel loginModel = new()
            {
                ResponseType = response_type,
                ClientId = client_id,
                RedirectUri = redirect_uri,
                Scope = scope,  
                State = state   
            };

            return View(loginModel);
        }

        public async Task<IActionResult> Logout() 
        { 
            await _signInManager.SignOutAsync();

            return Redirect("/Home");
        }


        [HttpPost]
        public async Task<IActionResult> Login(LoginModel loginModel)
        {
            if (ModelState.IsValid)
            {
                var applicationUser = await _userManager.FindByNameAsync(loginModel.Username);

                if (applicationUser is not null)
                {
                    var isCorrectCredentials = await _userManager.CheckPasswordAsync(applicationUser, loginModel.Password);

                    if (isCorrectCredentials)
                    {
                        await _signInManager.SignInAsync(applicationUser, false);

                        if(loginModel.ClientId is null)
                        {
                            return Redirect("/Home");
                        }

                        // Generate code
                        var code = _authenticationService.GenerateRandomString();

                        var query = new QueryBuilder();
                        query.Add("code", code);
                        query.Add("state", loginModel.State);
                        query.Add("username", applicationUser.UserName);

                        return Redirect($"{loginModel.RedirectUri}{query.ToString()}");
                    }

                    ModelState.AddModelError("error", "Please enter correct email and password.");

                    return View(loginModel);            
                }

                ModelState.AddModelError("error", "The username does not exist.");

                return View(loginModel);
            }

            return View(loginModel);
        }

        public async Task<IActionResult> Token(
            string grant_type
            ,string code
            ,string redirect_uri
            ,string client_id)
        {
            var token = _jwtHandler.GenerateToken();

            var responseObject = new
            {
                access_token = token,
                token_type = "Bearer"
            };

            var responseJson = JsonConvert.SerializeObject(responseObject);

            var responseBytes = Encoding.UTF8.GetBytes(responseJson); 

            await Response.Body.WriteAsync(responseBytes, 0, responseBytes.Length);

            return new EmptyResult();
        }

        //[Authorize]
        public async Task<JsonResult> UserClaims([FromQuery] 
            string username)
        {
            var applicationUser = await _userManager.FindByNameAsync(username);

            var claims = await _jwtHandler.GenerateClaims(applicationUser);

            return Json(claims);
        }

        public IActionResult ForgotPassword([FromQuery] string response_type
            , string client_id
            , string redirect_uri
            , string scope
            , string state)
        {
            ForgotPasswordModel forgotPasswordModel = new()
            {
                ResponseType = response_type,
                ClientId = client_id,
                RedirectUri = redirect_uri,
                Scope = scope,
                State = state
            };

            return View(forgotPasswordModel);
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel forgotPasswordModel)
        {
            if (ModelState.IsValid)
            {
                var result = await _authenticationService.SendPasswordRecoveryLink(forgotPasswordModel);

                if (result.IsSuccessful)
                {
                    forgotPasswordModel.ResetLinkSent = true;

                    return View(forgotPasswordModel);
                };

                forgotPasswordModel.ResetLinkSent = false;

                ModelState.AddModelError("error", result.Message);
            }
            
            forgotPasswordModel.ResetLinkSent = false;
            return View(forgotPasswordModel);
        }

        public IActionResult ResetPassword([FromQuery] string user_identifier
            , string token
            , string firstname
            , string response_type
            , string client_id
            , string redirect_uri
            , string scope
            , string state)
        {
            ResetPasswordModel resetPasswordModel = new()
            {
                UserIdentifier = user_identifier,
                Token = token,
                FirstName = firstname,
                ResponseType = response_type,
                ClientId = client_id,
                RedirectUri = redirect_uri,
                Scope = scope,
                State = state
            };

            return View(resetPasswordModel);
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        {
            if (ModelState.IsValid)
            {
                var result = await _authenticationService.ResetPassword(resetPasswordModel);

                if (result.IsSuccessful)
                {

                    NotifyUser("Password reset succesfully, Please enter new password to login", "Password Reset", NotificationType.success);

                    if (resetPasswordModel.ClientId is null)
                    {
                        return Redirect("/Account/Login");
                    }

                    return Redirect($"/Account/Login?response_type={resetPasswordModel.ResponseType}" +
                        $"&client_id={resetPasswordModel.ClientId}" +
                        $"&redirect_uri={resetPasswordModel.RedirectUri}" +
                        $"&scope={resetPasswordModel.Scope}" +
                        $"&state={resetPasswordModel.State}");
                }

                ModelState.AddModelError("error", result.Message);

                return View(resetPasswordModel);
            }

            return View(resetPasswordModel);
        }

        public IActionResult ActivateAccount([FromQuery] string user_identifier
            , string token
            , string firstname)
        {
            ActivateAccountModel activateAccountModel = new()
            {
                UserIdentifier = user_identifier,
                Token = token,
                FirstName = firstname,
            };

            return View(activateAccountModel);
        }

        [HttpPost]
        public async Task<IActionResult> ActivateAccount(ActivateAccountModel activateAccountModel)
        {
            if (ModelState.IsValid)
            {
                var result = await _authenticationService.ActivateAccount(activateAccountModel);

                if (result.IsSuccessful)
                {
                    NotifyUser("Account activated succesfully, Please login to access your account", "Account Activated", NotificationType.success);

                    return Redirect("/Account/Login");

                }

                ModelState.AddModelError("error", result.Message);
                return View(activateAccountModel);  
            }

            return View(activateAccountModel);
        }

        [Authorize]
        public async Task<IActionResult> UserDetails([FromQuery] string userId)
        {
            var result = await _authenticationService.GetUserAsync(userId);

            if (result.IsSuccessful)
            {
                var user = (ApplicationUser)result.Object;

                var userRole = _userManager.GetRolesAsync(user);
                
                return View(user);
            }

            NotifyUser("The requested user does not exist", "User Not Found", NotificationType.error);

            return Redirect("/Account/Users");
        }

        [Authorize]
        public async Task<IActionResult> Users()
        {
            IEnumerable<ApplicationUser> users = new List<ApplicationUser>();

            var result = await _authenticationService.GetUsersAsync();

            if (result.IsSuccessful)
            {
                users = (IEnumerable<ApplicationUser>)result.Object;              
            }

            return View(users);
        }

        [Authorize]
        public async Task<IActionResult> Profile()
        {
            var user = await _userManager.FindByEmailAsync(User.Identity.Name);

            if (user is not null)
            {
                return View(user);
            }

            NotifyUser("The requested user does not exist", "User Not Found", NotificationType.error);

            return Redirect("/Home");
        }
    }
}
