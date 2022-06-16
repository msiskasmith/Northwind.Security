using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class ActivateAccountModel : BaseModel
    {
        // User Identifier hidden from user
        public string UserIdentifier { get; set; }

        public string FirstName { get; set; }

        [MinLength(6, ErrorMessage = "Password cannot be less than 6 characters")]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        public string Password { get; set; }

        [MinLength(6, ErrorMessage = "Confirm Password cannot be less than 6 characters")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm Password")]
        public string ConfirmPassword { get; set; }

        public string Token { get; set; }

        public string UserFullName { get; set; }

        // From Oauth
        public string ResponseType { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }
        public string Scope { get; set; }
        public string State { get; set; }
    }
}
