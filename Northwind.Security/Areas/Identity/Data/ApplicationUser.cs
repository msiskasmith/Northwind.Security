using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Areas.Identity.Data
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }

        public string LastName { get; set; }    
    }
}
