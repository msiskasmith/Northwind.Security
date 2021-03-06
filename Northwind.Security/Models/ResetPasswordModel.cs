using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class ResetPasswordModel : BaseModel
    {
        // Username disabled input field
        public string UserIdentifier { get; set; }

        [MinLength(6, ErrorMessage = "New Password cannot be less than 6 characters")]
        [MaxLength(50, ErrorMessage = "New Password cannot be more than 50 characters.")]
        [DataType(DataType.Password)]
        [Display(Name ="New Password") ]
        public string NewPassword { get; set; }

        [MinLength(6, ErrorMessage = "Confirm New Password cannot be less than 6 characters")]
        [MaxLength(50, ErrorMessage = "Confirm Password cannot be more than 50 characters.")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage = "New Password and confirmation password do not match.")]
        public string ConfirmNewPassword { get; set; }

        public string Token { get; set; }
        public string FirstName { get; set; }    


        // From Oauth
        public string ResponseType { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }
        public string Scope { get; set; }
        public string State { get; set; }
    }
}
