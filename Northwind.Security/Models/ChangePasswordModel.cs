﻿using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class ChangePasswordModel
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
        public string ConfirmNewPassword { get; set; }
    }
}