using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Northwind.Security.Areas.Identity.Data;
using Northwind.Security.Helpers;
using Northwind.Security.Models;
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Northwind.Security.Areas.Identity.Services
{
    public class AuthenticationService : IAuthenticationService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly NorthwindSecurityContext _northwindSecurityContext;
        private readonly IConfiguration _configuration;
        private readonly IConfigurationSection _urls;
        private readonly IConfigurationSection _mailFrom;
        private readonly IMailService _mailService;
        private readonly IHostEnvironment _hostEnvironment;

        public AuthenticationService(UserManager<ApplicationUser> userManager
            , NorthwindSecurityContext northwindSecurityContext
            , IConfiguration configuration
            , IMailService mailService
            , IHostEnvironment hostEnvironment)
        {
            _userManager = userManager;
            _northwindSecurityContext = northwindSecurityContext;
            _configuration = configuration;
            _urls = _configuration.GetSection("Urls");
            _mailFrom = _configuration.GetSection("MailFrom");
            _mailService = mailService;
            _hostEnvironment = hostEnvironment;
        }
        public async Task<ProcessedResponse> Register(RegisterModel registerModel)
        {
            using (var transaction = _northwindSecurityContext.Database.BeginTransaction())
            {
                ApplicationUser applicationUser = new ApplicationUser()
                {
                    Email = registerModel.Username,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = registerModel.Username,
                    FirstName = registerModel.FirstName,
                    LastName = registerModel.LastName
                };

                var generatedPassword = GeneratePassword();

                var result = await _userManager.CreateAsync(applicationUser, generatedPassword);

                if (!result.Succeeded)
                {
                    // Get the errors and log them
                    var errors = string.Join(";", result.Errors.Select(x => x.Description));

                    return ResponseProcessor.GetValidationErrorResponse(
                        "Something went wrong, please contact your system admin");
                }

                var addRole = await _userManager.AddToRoleAsync(applicationUser, "UnActivatedUser");

                if (addRole.Succeeded)
                {
                    var confirmEmailToken = await _userManager.GenerateEmailConfirmationTokenAsync(applicationUser);

                    var encodedEmailToken = Encoding.UTF8.GetBytes(confirmEmailToken);

                    var validEmailToken = WebEncoders.Base64UrlEncode(encodedEmailToken);

                    string activationUrl = 
                        $"{_urls.GetSection("BaseUrl").Value}{_urls.GetSection("ActivateAccountUrl").Value}" +
                        $"username={applicationUser.UserName}&token={validEmailToken}";

                    var templatePath = Path.Combine(_hostEnvironment.ContentRootPath, "EmailTemplates"
                        , "ActivateAccount.cshtml");

                    EmailModel emailModel = new()
                    {
                        MailFrom = _mailFrom.Value,
                        MailTo = applicationUser.Email,
                        FirstName = applicationUser.FirstName,
                        LastName = applicationUser.LastName,
                        Url = activationUrl,
                        Password = generatedPassword

                    };

                    //Prevent from creating account if confirmation email is not sent

                    var sendEmail = await _mailService.SendEmailAsync(emailModel, templatePath);

                    if (sendEmail.IsSuccessful)
                    {
                        transaction.Commit();

                        return ResponseProcessor.GetSuccessResponse();
                    }

                    transaction.Rollback();
                    return ResponseProcessor.GetValidationErrorResponse(sendEmail.Message);
                }

                
                transaction.Rollback();

                // Should be logged  ot sent to user
                var addRoleErrors = string.Join(";", addRole.Errors.Select(x => x.Description));
                return ResponseProcessor.GetValidationErrorResponse(addRoleErrors);

            }
        }
        public async Task<ProcessedResponse> ActivateAccount(string username, string token)
        {
            var applicationUser = await _userManager.FindByNameAsync(username);

            if (applicationUser == null)
            {
                return ResponseProcessor.GetRecordNotFoundResponse("The user does not exist.");
            }

            var decodedToken = WebEncoders.Base64UrlDecode(token);
            var decodedTokenString = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ConfirmEmailAsync(applicationUser, decodedTokenString);

            if (result.Succeeded)
            {
                await _userManager.RemoveFromRoleAsync(applicationUser, "UnActivatedUser");

                await _userManager.AddToRoleAsync(applicationUser, "User");

                return ResponseProcessor.GetSuccessResponse();
            }

            return ResponseProcessor.GetValidationErrorResponse("Account activation failed, please try again");
        }

        public async Task<ProcessedResponse> SendPasswordRecoveryLink(ApplicationUser applicationUser
            , ForgotPasswordModel model)
        {
            var token = await _userManager.GeneratePasswordResetTokenAsync(applicationUser);

            var encodedToken = Encoding.UTF8.GetBytes(token);

            var validToken = WebEncoders.Base64UrlEncode(encodedToken);

            string recoveryUrl = 
                $"{_urls.GetSection("BaseUrl").Value}{_urls.GetSection("RecoverPasswordUrl").Value}" +
                $"username={applicationUser.UserName}&token={validToken}";

            var templatePath = Path.Combine(_hostEnvironment.ContentRootPath, "EmailTemplates", "RecoverPassword.cshtml");

            EmailModel emailModel = new()
            {
                MailFrom = _mailFrom.Value,
                MailTo = applicationUser.Email,
                FirstName = applicationUser.FirstName,
                LastName = applicationUser.LastName,
                Url = recoveryUrl
            };

            //Prevent from creating account if confirmation email is not sent
            var result = await _mailService.SendEmailAsync(emailModel, templatePath);

            return result;
        }

        public async Task<ProcessedResponse> ResetPassword(ApplicationUser applicationUser
            , ResetPasswordModel resetPasswordModel)
        {
            var decodedToken = WebEncoders.Base64UrlDecode(resetPasswordModel.Token);

            var decodedTokenString = Encoding.UTF8.GetString(decodedToken);

            var result = await _userManager.ResetPasswordAsync(
                applicationUser, decodedTokenString, resetPasswordModel.NewPassword);

            if (result.Succeeded)
            {
                return ResponseProcessor.GetSuccessResponse();
            }

            return ResponseProcessor.GetValidationErrorResponse(
                "Password was not reset, please try again or contact your system administrator");
        }

        public string GeneratePassword()
        {
            const string validPasswordCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

            StringBuilder stringBuilder = new StringBuilder();

            Random randomNumber = new Random();

            var i = 0;

            var length = 10;

            while (i < length--)
            {
                stringBuilder.Append(validPasswordCharacters[randomNumber.Next(validPasswordCharacters.Length)]);
            }

            return stringBuilder.ToString();
        }
    }
}
