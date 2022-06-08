namespace Northwind.Security.Models
{
    public class ActivateAccountModel : EmailModel
    {
        public string Username { get; set; }
        public string Token { get; set; }
    }
}
