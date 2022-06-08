using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class ForgotPasswordModel
    {
        [EmailAddress(ErrorMessage ="Please provide a valid email address.")]
        [Required(ErrorMessage ="Email cannot be empty.")]
        [MinLength(7, ErrorMessage ="Email cannot be less than 7 characters.")]
        [Display(Name ="Email")]
        public string Username { get; set; }
    }
}
