using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using jwt_token_implementation.Models;
using jwt_token_implementation.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace jwt_token_implementation.Controllers
{
    [Route("api/user")]
    [Authorize]
    [ApiController]
    public class UserController : Controller
    {
        private readonly IAuthenticationService _authenticationService;
        private readonly IConfiguration _configuration;
        private string _userId;

        public UserController(IAuthenticationService authenticationService, IConfiguration configuration)
        {
            _configuration = configuration;
            _authenticationService = authenticationService;
            _userId = _authenticationService.GetUserId();
            //_userId = _authenticationService.GetCurrentuser();
        }

        [AllowAnonymous]
        [HttpPost("token")]
        public IActionResult Login([FromBody] UserLogin userLogin)
        {
            bool userStatus = _authenticationService.AuthenticateUser(userLogin);
            int tokenValidity = _configuration.GetValue<int>("JwtToken:TokenExpiry");

            byte[] username = ASCIIEncoding.ASCII.GetBytes(userLogin.Username);
            string usernameEncode = Convert.ToBase64String(username);

            if (userStatus)
            {
                var token = _authenticationService.GenerateToken(userLogin.Username);
                return Ok(new { Token = token, TokenValidity = tokenValidity, U = usernameEncode });
            }
            return NotFound("Username or password is invalid, try again with valid username or password");
        }

        [HttpGet("users")]
        public IActionResult GetUsers()
        {
            var users = UserData.UserRecords.Select(a => new
            {
                FirstName = a.FirstName,
                Surname = a.Surname,
                EmailAdress = a.EmailAdress,
                Username = a.Username,
                UserRole = a.UserRole,
            });

            return Ok(users);
        }

        [HttpGet("{username}")]
        public IActionResult GetUser(string username)
        {
            var users = UserData.UserRecords.Where(b => b.Username == username.ToLower()).Select(a => new
            {
                FirstName = a.FirstName,
                Surname = a.Surname,
                EmailAdress = a.EmailAdress,
                Username = a.Username,
                UserRole = a.UserRole,
            });

            return Ok(users);
        }

        [HttpGet("user-id")]
        public IActionResult GetUserId()
        {
            //var userId = _authenticationService.GetUserId();
            //var userId = _authenticationService.GetCurrentuser();
            var userId = _userId;

            return Ok(userId);
        }

    }
}

