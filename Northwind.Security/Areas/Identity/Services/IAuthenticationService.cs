using Northwind.Security.Areas.Identity.Data;
using Northwind.Security.Models;
using System.Threading.Tasks;

namespace Northwind.Security.Areas.Identity.Services
{
    public interface IAuthenticationService
    {
        public Task<ProcessedResponse> Register(RegisterModel registerModel);
        public Task<ProcessedResponse> SendPasswordRecoveryLink(ForgotPasswordModel forgotPasswordModel);
        public Task<ProcessedResponse> ResetPassword(ResetPasswordModel resetPasswordModel);
        public Task<ProcessedResponse> ActivateAccount(ActivateAccountModel activateAccountModel);
        public string GenerateRandomString(int stringLength = 10);
    }
}
