using Northwind.Security.Areas.Identity.Data;
using Northwind.Security.Models;
using System.Threading.Tasks;

namespace Northwind.Security.Areas.Identity.Services
{
    public interface IAuthenticationService
    {
        public Task<ProcessedResponse> Register(RegisterModel registerModel);
        public Task<ProcessedResponse> SendPasswordRecoveryLink(ApplicationUser applicationUser, ForgotPasswordModel model);
        public Task<ProcessedResponse> ResetPassword(ApplicationUser applicationUser, ResetPasswordModel model);
        public Task<ProcessedResponse> ActivateAccount(string username, string token);
    }
}
