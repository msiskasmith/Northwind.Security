using AutoMapper;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
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
        private readonly ILogger<AuthenticationService> _logger;

        public AuthenticationService(UserManager<ApplicationUser> userManager
            , NorthwindSecurityContext northwindSecurityContext
            , IConfiguration configuration
            , IMailService mailService
            , IHostEnvironment hostEnvironment
            , ILogger<AuthenticationService> logger)
        {
            _userManager = userManager;
            _northwindSecurityContext = northwindSecurityContext;
            _configuration = configuration;
            _urls = _configuration.GetSection("Urls");
            _mailFrom = _configuration.GetSection("MailFrom");
            _mailService = mailService;
            _hostEnvironment = hostEnvironment;
            _logger = logger;
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

                var generatedPassword = GenerateRandomString();

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

                    // Encrypt token
                    var encodedEmailToken = EncodeString(confirmEmailToken);

                    // Encrypt email
                    var encodedUsername = EncodeString(registerModel.Username);   

                    // Create activation url
                    string activationUrl = 
                        $"{_urls.GetSection("BaseUrl").Value}{_urls.GetSection("ActivateAccountUrl").Value}" +
                        $"&firstname={applicationUser.FirstName}&lastname={applicationUser.LastName}" +
                        $"useridentifier={encodedUsername}" +
                        $"&token={encodedEmailToken}" +
                        $"&response_type={registerModel.ResponseType}" +
                        $"&client_id={registerModel.ClientId}" +
                        $"&redirect_uri={registerModel.RedirectUri}" +
                        $"&scope={registerModel.Scope}" +
                        $"&state={registerModel.State}";

                    var templatePath = Path.Combine(_hostEnvironment.ContentRootPath, "EmailTemplates"
                        , "ActivateAccount.cshtml");

                    EmailModel emailModel = new()
                    {
                        MailFrom = _mailFrom.Value,
                        MailTo = applicationUser.Email,
                        FirstName = applicationUser.FirstName,
                        LastName = applicationUser.LastName,
                        Url = activationUrl,
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

                var addRoleErrors = string.Join(";", addRole.Errors.Select(x => x.Description));

                return ResponseProcessor.GetValidationErrorResponse("User was not added, Please contact your System Administrator");

            }
        }
        public async Task<ProcessedResponse> ActivateAccount(ActivateAccountModel activateAccountModel)
        {
            // Decode the username
            var username = DecodeString(activateAccountModel.UserIdentifier);

            // Decode token
            var token = DecodeString(activateAccountModel.Token);

            // Find user by username
            var applicationUser = await _userManager.FindByEmailAsync(username);

            if (applicationUser == null)
            {
                return ResponseProcessor.GetRecordNotFoundResponse("The user does not exist.");
            }          

            // Start transaction
            using (var transaction = _northwindSecurityContext.Database.BeginTransaction())
            {
                // Confirm email
                var result = await _userManager.ConfirmEmailAsync(applicationUser, token);

                if (result.Succeeded)
                {
                    // Reset password with user password
                    var passwordResetToken = await _userManager.GeneratePasswordResetTokenAsync(applicationUser);

                    await _userManager.ResetPasswordAsync(
                    applicationUser, passwordResetToken, activateAccountModel.Password);

                    // Change user role
                    await _userManager.RemoveFromRoleAsync(applicationUser, "UnActivatedUser");

                    await _userManager.AddToRoleAsync(applicationUser, "User");

                    transaction.Commit();
                    // Send success message
                    return ResponseProcessor.GetSuccessResponse();
                }

                transaction.Rollback();
            }
            
            return ResponseProcessor.GetValidationErrorResponse("Account activation failed, please try again");
        }

        public async Task<ProcessedResponse> SendPasswordRecoveryLink(ForgotPasswordModel forgotPasswordModel)
        {
            var applicationUser = await _userManager.FindByEmailAsync(forgotPasswordModel.Username);

            if(applicationUser == null)
            {
                return ResponseProcessor.GetValidationErrorResponse("The user does not exist.");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(applicationUser);

            // Encode token
            var encodedToken = EncodeString(token);

            // Decode Token
            var encodedUsername = EncodeString(applicationUser.UserName);    

            string recoveryUrl = 
                $"{_urls.GetSection("BaseUrl").Value}{_urls.GetSection("RecoverPasswordUrl").Value}" +
                $"useridentifier={encodedUsername}&token={encodedToken}" +
                $"&response_type={forgotPasswordModel.ResponseType}" +
                $"&client_id={forgotPasswordModel.ClientId}" +
                $"&redirect_uri={forgotPasswordModel.RedirectUri}" +
                $"&scope={forgotPasswordModel.Scope}" +
                $"&state={forgotPasswordModel.State}";

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

        public async Task<ProcessedResponse> ResetPassword(ResetPasswordModel resetPasswordModel)
        {

            var token = DecodeString(resetPasswordModel.Token);
            var username = DecodeString(resetPasswordModel.UserIdentifier);

            var applicationUser = await _userManager.FindByEmailAsync(username);

            if(applicationUser is null)
            {
                return ResponseProcessor.GetValidationErrorResponse("User does not exist");
            }

            var result = await _userManager.ResetPasswordAsync(
                applicationUser, token, resetPasswordModel.NewPassword);

            if (result.Succeeded)
            {
                return ResponseProcessor.GetSuccessResponse();
            }

            return ResponseProcessor.GetValidationErrorResponse(
                "Password was not reset, please try again or contact your system administrator");
        }

        public string EncodeString(string stringToEncode)
        {
            var result = Encoding.UTF8.GetBytes(stringToEncode);

            var urlSafeString = WebEncoders.Base64UrlEncode(result);

            return urlSafeString;
        }

        public string DecodeString(string stringToDecode)
        {
            var result = WebEncoders.Base64UrlDecode(stringToDecode);

            var decodedString = Encoding.UTF8.GetString(result);

            return decodedString;
        }

        public string GenerateRandomString(int stringLength = 10)
        {
            const string validCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";

            StringBuilder stringBuilder = new StringBuilder();

            Random randomNumber = new Random();

            var i = 0;

            while (i < stringLength--)
            {
                stringBuilder.Append(validCharacters[randomNumber.Next(validCharacters.Length)]);
            }

            return stringBuilder.ToString();
        }
    }
}
