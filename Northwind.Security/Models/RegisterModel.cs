using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public partial class RegisterModel
    {
        [Required(ErrorMessage = "First Name is required")]
        [MinLength(3, ErrorMessage = "First Name cannot be less than 3 characters.")]
        [MaxLength(50, ErrorMessage = "First Name cannot be more than 50 characters.")]
        [Display(Name = "First Name")]
        public string FirstName { get; set; }

        [Required(ErrorMessage = "Last Name is required")]
        [MinLength(3, ErrorMessage = "Last Name cannot be less than 3 characters.")]
        [MaxLength(50, ErrorMessage = "Last Name cannot be more than 50 characters.")]
        [Display(Name ="Last Name")]
        public string LastName { get; set; }

        [EmailAddress(ErrorMessage ="Please provide a valid email.")]
        [Required]
        [Display(Name ="Email")]
        [MinLength(7, ErrorMessage ="Email cannot be less than 7 characters")]
        [MaxLength(256, ErrorMessage ="Email cannot be more than 256 characters")]
        public string Username { get; set; }
    }
}
