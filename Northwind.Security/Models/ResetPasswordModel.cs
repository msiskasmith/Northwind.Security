﻿using System.ComponentModel.DataAnnotations;

namespace Northwind.Security.Models
{
    public class ResetPasswordModel
    {
        // Username disabled input field
        public string Username { get; set; }

        [MinLength(6, ErrorMessage = "New Password cannot be less than 6 characters")]
        [MaxLength(50, ErrorMessage = "New Password cannot be more than 50 characters.")]
        [DataType(DataType.Password)]
        [Display(Name ="New Password") ]
        public string NewPassword { get; set; }

        [MinLength(6, ErrorMessage = "Confirm New Password cannot be less than 6 characters")]
        [MaxLength(50, ErrorMessage = "Confirm Password cannot be more than 50 characters.")]
        [DataType(DataType.Password)]
        [Display(Name = "Confirm New Password")]
        public string ConfirmNewPassword { get; set; }

        public string Token { get; set; }
    }
}