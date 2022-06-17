using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class ChangePasswordModel : BaseModel
    {
        // Username disabled input field
        public string Username { get; set; }

        [MinLength(6, ErrorMessage = "Current Password cannot be less than 6 characters")]
        [DataType(DataType.Password)]
        [Display(Name = "Current Password")]
        public string CurrentPassword { get; set; }

        [MinLength(6, ErrorMessage = "New Password cannot be less than 6 characters")]
        [DataType(DataType.Password)]
        [Display(Name = "New Password")]
        public string NewPassword { get; set; }

        [MinLength(6, ErrorMessage = "Confirm New Password cannot be less than 6 characters")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        [Compare("NewPassword", ErrorMessage = "New Password and confirmation password do not match.")]
        public string ConfirmNewPassword { get; set; }


        // From Oauth
        public string ResponseType { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }
        public string Scope { get; set; }
        public string State { get; set; }
    }
}
