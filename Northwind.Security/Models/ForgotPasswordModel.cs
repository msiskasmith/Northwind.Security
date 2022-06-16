using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class ForgotPasswordModel : BaseModel
    {
        [EmailAddress(ErrorMessage ="Please provide a valid email address.")]
        [Required(ErrorMessage ="Email cannot be empty.")]
        [MinLength(7, ErrorMessage ="Email cannot be less than 7 characters.")]
        [Display(Name ="Email")]
        public string Username { get; set; }

        public bool ResetLinkSent { get; set; } = false;

        // From Oauth
        public string ResponseType { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }
        public string Scope { get; set; }
        public string State { get; set; }
    }
}
