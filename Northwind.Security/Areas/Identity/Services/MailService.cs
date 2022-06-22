using System;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;
using Northwind.Security.Models;
using System.Text;
using System.Threading.Tasks;
using FluentEmail.Core;
using FluentEmail.Razor;
using FluentEmail.Smtp;
using Northwind.Security.Helpers;

namespace Northwind.Security.Areas.Identity.Services
{
    public class MailService : IMailService
    {
        private readonly IConfiguration _configuration;
        private readonly IConfigurationSection _smtpSettings;

        public MailService(IConfiguration configuration)
        {
            _configuration = configuration;
            _smtpSettings = _configuration.GetSection("SmtpClient");
        }
        public async Task<ProcessedResponse> SendEmailAsync(EmailModel emailModel, string templatePath)
        {
            var sender = new SmtpSender(() => new SmtpClient(_smtpSettings.GetSection("Host").Value)
            {
                Credentials = new System.Net.NetworkCredential(_smtpSettings.GetSection("UserName").Value, _smtpSettings.GetSection("Password").Value),
                EnableSsl = Convert.ToBoolean(_smtpSettings.GetSection("EnableSsl").Value),
                DeliveryMethod = SmtpDeliveryMethod.Network,
                Port = Convert.ToInt32(_smtpSettings.GetSection("Port").Value)
            });

            Email.DefaultSender = sender;
            Email.DefaultRenderer = new RazorRenderer();

            var email = await Email.From(emailModel.MailFrom)
                                    .To(emailModel.MailTo, emailModel.FullName)
                                    .Subject(emailModel.Subject)
                                    .UsingTemplateFromFile(templatePath, emailModel)
                                    .SendAsync();

            if (email.Successful)
            {
                return ResponseProcessor.GetSuccessResponse();
            }

            return ResponseProcessor.GetValidationErrorResponse(email.ErrorMessages.ToString());
        }
    }
}
