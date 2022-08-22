using System;
namespace jwt_token_implementation.Models
{
    //public class UserModel
    //{
    //    //public UserModel()
    //    //{
    //    //}
    //}

    public class Users
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string EmailAdress { get; set; }
        public string UserRole { get; set; }
        public string FirstName { get; set; }
        public string Surname { get; set; }
    }

    public class UserLogin
    {
        public string Username { get; set; }
        public string Password { get; set; }

    }
}

