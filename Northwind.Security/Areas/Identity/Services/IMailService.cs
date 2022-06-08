using Northwind.Security.Models;
using System.Text;
using System.Threading.Tasks;

namespace Northwind.Security.Areas.Identity.Services
{
    public interface IMailService
    {
        Task<ProcessedResponse> SendEmailAsync(EmailModel emailModel, string templatePath);
    }
}
