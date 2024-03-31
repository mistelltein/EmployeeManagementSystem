using EMS.BaseLibrary.DTOs;
using EMS.ServerLibrary.Repositories.Contracts;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace EMS.Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IUserAccount _accountInterface;

        public AuthenticationController(IUserAccount accountInterface)
        {
            _accountInterface = accountInterface;
        }

        [HttpPost("register")]
        public async Task<IActionResult> CreateAsync(Register user)
        {
            if (user is null)
                return BadRequest("Model is empty");

            var result = await _accountInterface.CreateAsync(user);

            return Ok(result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> SignInAsync(Login user)
        {
            if (user is null)
                return BadRequest("Model is empty");

            var result = await _accountInterface.SignInAsync(user);

            return Ok(result);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshTokenAsync(RefreshToken token)
        {
            if (token is null)
                return BadRequest("Model is empty");

            var result = await _accountInterface.RefreshTokenAsync(token);

            return Ok(result);
        }
    }
}
