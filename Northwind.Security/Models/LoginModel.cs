using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class LoginModel : BaseModel
    {
        [EmailAddress]
        [Display(Name = "Username")]
        [Required(ErrorMessage = "Username is required.")]
        [MinLength(6, ErrorMessage = "Username cannot be less than 6 characters.")]
        [MaxLength(256, ErrorMessage = "Username cannot be more than 256 characters.")]
        public string Username { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [MinLength(6, ErrorMessage = "Password cannot be less than 6 characters")]
        [MaxLength(50, ErrorMessage = "Password cannot be more than 50 characters.")]
        public string Password { get; set; }

        // From Oauth
        public string ResponseType { get; set; }
        public string ClientId { get; set; }
        public string RedirectUri { get; set; }
        public string Scope { get; set; }
        public string State { get; set; }   
    }
}
