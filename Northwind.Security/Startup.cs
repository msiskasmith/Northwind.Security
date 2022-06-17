using AutoMapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Northwind.Security.Areas.Identity.Data;
using Northwind.Security.Areas.Identity.Services;
using Northwind.Security.Authentication.JwtFeatures;
using Northwind.Security.Helpers;
using System;
using System.Text;
using System.Threading.Tasks;

namespace Northwind.Security
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews()
                .AddRazorRuntimeCompilation();

            services.AddRazorPages();

            services.AddHttpClient();
            services.AddHttpClient("authentication", (sp, c) =>
            {
                c.BaseAddress = new Uri(Configuration.GetValue<string>("apiLocation"));
            });

            services.AddScoped<IAuthenticationService, AuthenticationService>();
            services.AddScoped<IMailService, MailService>();
            services.AddScoped<JwtHandler>();

            // Auto Mapper Configurations
            var mapperConfig = new MapperConfiguration(mc =>
            {
                mc.AddProfile(new MappingProfile());
            });

            IMapper mapper = mapperConfig.CreateMapper();

            services.AddSingleton(mapper);

            // End Auto mapper config

            services.AddDbContext<NorthwindSecurityContext>(options =>
                    options.UseNpgsql(Configuration.GetConnectionString("NorthwindSecurityContextConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>(
                options => options.SignIn.RequireConfirmedAccount = false)
                .AddEntityFrameworkStores<NorthwindSecurityContext>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.RequireHttpsMetadata = false;
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidIssuer = Configuration["AuthSettings:Issuer"],
                        ValidAudience = Configuration["AuthSettings:Audience"],
                        RequireExpirationTime = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["AuthSettings:Key"])),
                        ValidateIssuerSigningKey = true,
                        // set clockskew to zero so tokens expire exactly at token expiration time (instead of 5 minutes later)
                        ClockSkew = TimeSpan.Zero
                    };
                    
                    options.Events = new JwtBearerEvents
                    {
                        OnTokenValidated = context =>
                        {
                            var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
                            var user = userManager.GetUserAsync(context.HttpContext.User);

                            if (user is null)
                            {
                                context.Fail("UnAuthorized ");
                            }                              
                            return Task.CompletedTask;
                        }
                    };

                    options.RequireHttpsMetadata = false;
                    options.SaveToken = true;

                    options.Configuration = new OpenIdConnectConfiguration();
                })
                .AddCookie(options =>
                {
                    options.Cookie.Name = "NorthwindSecurity.UserManager.Cookie";
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SameSite = SameSiteMode.None;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    options.Cookie.IsEssential = true;
                    options.SlidingExpiration = true;
                });

            services.Configure<IdentityOptions>(options =>
            {
                // Password settings.
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = true;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 0;

                // Lockout settings.
                options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
                options.Lockout.MaxFailedAccessAttempts = 5;
                options.Lockout.AllowedForNewUsers = true;

                // User settings.
                options.User.AllowedUserNameCharacters =
                "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
                options.User.RequireUniqueEmail = false;
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();
           
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");

                endpoints.MapRazorPages();
            });
        }
    }
}
