using Microsoft.AspNetCore.Identity;
using Northwind.Security.Areas.Identity.Data;
using System.Collections.Generic;

namespace Northwind.Security.Models
{
    public class EditUserRoleViewModel
    {
        public ApplicationUser User { get; set; }
        public string UserRole { get; set; }
        public IEnumerable<IdentityRole> Roles { get; set; }
    }
}
