using System;
namespace jwt_token_implementation.Models
{
    public class UserData
    {
        //public UserData()
        //{
        //}

        public static List<Users> UserRecords = new List<Users>()
        {

            new Users ()
            {
                Username="eokon",
                EmailAdress="eokon@mail.com",
                Password="password",
                FirstName="Emmanuel",
                Surname="Okon",
                UserRole="Super Admin"
            },
             new Users ()
            {
                Username="jummycg",
                EmailAdress="jummycg@mail.com",
                Password="password",
                FirstName="Jummy",
                Surname="Ukor",
                UserRole="User"
            },
             new Users ()
            {
                Username="bagboola",
                EmailAdress="bagboola@mail.com",
                Password="password",
                FirstName="Busola",
                Surname="Agboola",
                UserRole="User"
            },
             new Users ()
            {
                Username="yolatunji",
                EmailAdress="yolatunji@mail.com",
                Password="password",
                FirstName="Yomi",
                Surname="Olatunji",
                UserRole="Admin"
            },

        };
    }
}

