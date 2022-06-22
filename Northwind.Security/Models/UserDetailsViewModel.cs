using Northwind.Security.Areas.Identity.Data;
using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class UserDetailsViewModel
    {
        public ApplicationUser User { get; set; }
        
        [Display(Name="User Role")]
        public string Role { get; set; }
    }
}
