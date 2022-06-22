using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Northwind.Security.Areas.Identity.Data;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Northwind.Security.Authentication.JwtFeatures
{
    public class JwtHandler
    {
		private readonly IConfiguration _configuration;
		private readonly IConfigurationSection _jwtSettings;
		private readonly UserManager<ApplicationUser> _userManager;
		public JwtHandler(IConfiguration configuration, UserManager<ApplicationUser> userManager)
		{
			_userManager = userManager;
			_configuration = configuration;
			_jwtSettings = _configuration.GetSection("AuthSettings");
		}

		private SigningCredentials GetSigningCredentials()
		{
			var key = Encoding.ASCII.GetBytes(_jwtSettings["Key"]);
			var secret = new SymmetricSecurityKey(key);
			return new SigningCredentials(secret, SecurityAlgorithms.HmacSha256Signature);
		}

		private async Task<List<Claim>> GetClaims(ApplicationUser user)
		{
			var claims = new List<Claim>
			{
				 new Claim(ClaimTypes.Name, user.UserName),
				 new Claim(ClaimTypes.NameIdentifier, user.Id),
				 new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
			};

			var roles = await _userManager.GetRolesAsync(user);
			
			foreach (var role in roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role));
			}

			return claims;
		}

		public string GenerateToken()
		{
			var signingCredentials = GetSigningCredentials();
			var tokenOptions = GenerateTokenOptions(signingCredentials);
			var token = new JwtSecurityTokenHandler().WriteToken(tokenOptions);

			return token;
		}

		private JwtSecurityToken GenerateTokenOptions(SigningCredentials signingCredentials)
		{
			var tokenOptions = new JwtSecurityToken(
				issuer: _jwtSettings["ValidIssuer"],
				audience: _jwtSettings["ValidAudience"],
				expires: DateTime.Now.AddMinutes(Convert.ToDouble(_jwtSettings.GetSection("ExpiryInMinutes").Value)),
				signingCredentials: signingCredentials
				);

			return tokenOptions;
		}

		public async Task<IEnumerable<Claim>> GenerateClaims(ApplicationUser applicationUser)
        {
			var claims = await GetClaims(applicationUser);

			return claims;
		}
	}
}
