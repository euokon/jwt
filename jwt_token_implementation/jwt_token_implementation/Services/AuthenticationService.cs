using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using jwt_token_implementation.Models;
using Microsoft.IdentityModel.Tokens;

namespace jwt_token_implementation.Services
{
    public interface IAuthenticationService
    {
        bool AuthenticateUser(UserLogin userLogin);
        string GenerateToken(string userId);
        ClaimsPrincipal GetPrincipal(string token);
        IPrincipal AuthenticateJwtToken(string token);
        string GetUserId();
        string GetCurrentuser();
    }

    public class AuthenticationService : IAuthenticationService
    {
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _httpContextAccessor;

        public AuthenticationService(IConfiguration configuration, IHttpContextAccessor httpContextAccessor)
        {
            _configuration = configuration;
            _httpContextAccessor = httpContextAccessor;
        }

        public bool AuthenticateUser(UserLogin userLogin)
        {
            bool userStatus;

            var loginUser = UserData.UserRecords.Where(x => x.Username == userLogin.Username.ToLower())
                                                .FirstOrDefault(y => y.Username == userLogin.Username.ToLower()
                                                && y.Password == userLogin.Password);
            if (loginUser != null)
            {
                userStatus = true;
            }
            else
            {
                userStatus = false;
            }

            return userStatus;
        }

        public string GenerateToken(string userId)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("JwtToken:SecretKey")));
            var credentials = new SigningCredentials(securitykey, SecurityAlgorithms.HmacSha256);
            var jwtValidity = DateTime.Now.AddMinutes(_configuration.GetValue<int>("JwtToken:TokenExpiry"));
            IEnumerable<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, userId)
            };

            var token = new JwtSecurityToken(_configuration.GetValue<string>("JwtToken:Issuer"), _configuration.GetValue<string>("JwtToken:Audience"), claims, expires: jwtValidity, signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private bool ValidateToken(string token, out string username)
        {
            username = null;

            var simplePrinciple = GetPrincipal(token);
            var identity = simplePrinciple?.Identity as ClaimsIdentity;

            if (identity == null)
                return false;

            if (!identity.IsAuthenticated)
                return false;
            var usernameClaim = identity.FindFirst(ClaimTypes.NameIdentifier);
            username = usernameClaim?.Value;

            if (string.IsNullOrEmpty(username))
                return false;
            return true;
        }

        public IPrincipal AuthenticateJwtToken(string token)
        {
            if (ValidateToken(token, out var username))
            {
                // based on username to get more information from database in order to build local identity
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, username)
                    // Add more claims if needed: Roles, ...
                };

                var identity = new ClaimsIdentity(claims, "Jwt");
                IPrincipal user = new ClaimsPrincipal(identity);

                return user;
            }

            return null;
        }

        public ClaimsPrincipal GetPrincipal(string token)
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

                if (jwtToken == null)
                    return null;
                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetValue<string>("JwtToken:SecretKey")));

                var validationParameters = new TokenValidationParameters()
                {
                    RequireExpirationTime = true,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    IssuerSigningKey = key
                };

                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
                return principal;
            }
            catch (SecurityTokenExpiredException e)
            {
                return null;
            }
        }

        public string GetUserId()
        {
            var authorization = _httpContextAccessor.HttpContext.Request.Headers["Authorization"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(authorization))
                return null;
            string token = authorization.Split(" ")[1].Trim();
            var simplePrinciple = GetPrincipal(token);
            var identity = simplePrinciple?.Identity as ClaimsIdentity;

            if (identity == null || !identity.IsAuthenticated)
                return null;
            var usernameClaim = identity.FindFirst(ClaimTypes.NameIdentifier);
            string username = usernameClaim?.Value;

            return username;
        }

        public string GetCurrentuser()
        {
            var identity = _httpContextAccessor.HttpContext.User?.Identity as ClaimsIdentity;

            if (identity != null)
            {
                //var usernameClaim = identity.FindFirst(ClaimTypes.NameIdentifier);
                //string username = usernameClaim?.Value;

                var userClaims = identity.Claims;
                string username = userClaims.FirstOrDefault(a => a.Type == ClaimTypes.NameIdentifier)?.Value;

                return username;
            }
            return null;
        }

    }
}

