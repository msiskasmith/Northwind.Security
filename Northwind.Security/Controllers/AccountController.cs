
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json;

using Northwind.Security.Areas.Identity.Data;
using Northwind.Security.Areas.Identity.Services;
using Northwind.Security.Authentication.JwtFeatures;
using Northwind.Security.Models;
using System.Text;
using System.Threading.Tasks;

namespace Northwind.Security.Controllers
{
    public class AccountController : BaseController
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly JwtHandler _jwtHandler;
        private readonly IAuthenticationService _authenticationService;

        public AccountController(UserManager<ApplicationUser> userManager
            , IConfiguration configuration
            , JwtHandler jwtHandler
            , IAuthenticationService authenticationService)
        {
            _userManager = userManager;
            _configuration = configuration;
            _jwtHandler = jwtHandler;
            _authenticationService = authenticationService;
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
                        // Generate code
                        var code = _authenticationService.GenerateRandomString();

                        var query = new QueryBuilder();
                        query.Add("code", code);
                        query.Add("state", loginModel.State);
                        query.Add("username", applicationUser.UserName);

                        return Redirect($"{loginModel.RedirectUri}{query.ToString()}");
                    }

                    // Change to redirect to login

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
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel forgotPasswordModel)
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

        public IActionResult ResetPassword()
        {
            return View();
        }

        //[HttpPost]
        //public async Task<IActionResult> ResetPassword(ResetPasswordModel resetPasswordModel)
        //{
        //    if (ModelState.IsValid)
        //    {
        //        var client = _httpClientFactory.CreateClient("authentication");

        //        var response = await client.PostAsJsonAsync($"Authenticate/ResetPassword"
        //            , resetPasswordModel);

        //        if (response.IsSuccessStatusCode == false)
        //        {
        //            NotifyUser(response.Content.ReadAsStringAsync().Result,
        //            "Password Reset Failed", NotificationType.error);

        //            CreateObjectCookie("ResetPasswordModelCookie", resetPasswordModel);

        //            return Redirect("/Account/ResetPassword");
        //        }
        //    }

        //    return View(resetPasswordModel);
        //}

        public IActionResult ActivateAccount()
        {
            ActivateAccountModel activateAccountModel = new()
            {
                FirstName = "Smith"
            };

            return View(activateAccountModel);
        }

        //[HttpPost]
        //public async Task<IActionResult> ActivateAccount([FromBody] ActivateAccountModel activateAccountModel)
        //{
        //    if (ModelState.IsValid)
        //    {
        //        var client = _httpClientFactory.CreateClient("authentication");

        //        var response = await client.PostAsJsonAsync($"Authenticate/ActivateAccount"
        //            , activateAccountModel);

        //        if (response.IsSuccessStatusCode == false)
        //        {
        //            NotifyUser(response.Content.ReadAsStringAsync().Result,
        //            "Account Activation Failed", NotificationType.error);

        //            CreateObjectCookie("ActivateAccountModelCookie", activateAccountModel);

        //            return Redirect("/Account/ActivateAccount");
        //        }
        //    }

        //    return View(activateAccountModel);
        //}
    }
}
