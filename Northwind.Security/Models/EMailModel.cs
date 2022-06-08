namespace Northwind.Security.Models
{
    public partial class EmailModel
    {
        public string MailFrom { get; set; }
        public string MailTo { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Url { get; set; }
        public string Password { get; set; }
        public string FullName
        {
            get
            {
                return $"{FirstName} {LastName}";
            }
        }
        public string Subject { get; set; }
    }
}
