using System.Security.Claims;
using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Auth0DualStartup.Controllers
{
    [ApiController]
    public class ProfileController : Controller
    {
        private readonly ILogger<ProfileController> _logger;

        public ProfileController(ILogger<ProfileController> logger)
        {
            this._logger = logger;
        }

        [HttpGet("/login", Name = "login")]
        public async Task Login()
        {
            var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
                // Indicate here where Auth0 should redirect the user after a login.
                // Note that the resulting absolute Uri must be added to the
                // **Allowed Callback URLs** settings for the app.
                .WithRedirectUri("/profile")
                .Build();

            await HttpContext.ChallengeAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
        }

        [Authorize]
        [HttpGet("/logout", Name = "logout")]
        public async Task Logout()
        {
            var authenticationProperties = new LogoutAuthenticationPropertiesBuilder()
                // Indicate here where Auth0 should redirect the user after a logout.
                // Note that the resulting absolute Uri must be added to the
                // **Allowed Logout URLs** settings for the app.
                .WithRedirectUri("/swagger")
                .Build();

            // Logout from Auth0
            await HttpContext.SignOutAsync(Auth0Constants.AuthenticationScheme, authenticationProperties);
            
            // Logout from the application
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }

        [HttpGet("/open", Name = "open")]
        public IActionResult OpenAccess() => base.Ok("this is open");

        [Authorize]
        [HttpGet("/profile", Name = "profile")]
        public IActionResult Profile()
        {
            var profile = new ProfileDto(
                User.Identity.Name,
                User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value);

            return base.Ok(profile);
        }

        private readonly record struct ProfileDto(string Name, string EmailAddress);
    }
}
