using AutoMapper;
using Northwind.DataModels.Authentication;
using Northwind.Security.Areas.Identity.Data;
using Northwind.Security.Models;

namespace Northwind.Security.Helpers
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<ApplicationUser, UserDto>().ReverseMap();
            CreateMap<RegisterModel, RegisterUserDto>().ReverseMap();
        }       
    }
}
