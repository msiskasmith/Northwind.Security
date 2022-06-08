using Microsoft.EntityFrameworkCore.Migrations;

namespace Northwind.Security.Migrations
{
    public partial class AddFirstNameAndLastNameToApplicationUser : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "FirstName",
                schema: "public",
                table: "ApplicationUser",
                type: "character varying(50)",
                maxLength : 50,
                nullable: false);

            migrationBuilder.AddColumn<string>(
                name: "LastName",
                schema: "public",
                table: "ApplicationUser",
                type: "character varying(50)",
                maxLength: 50,
                nullable: false);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "FirstName",
                schema: "public",
                table: "ApplicationUser");

            migrationBuilder.DropColumn(
                name: "LastName",
                schema: "public",
                table: "ApplicationUser");
        }
    }
}
