using System;
using System.Linq;
using Bogus;
using Bogus.Extensions;

namespace netstandard2._1.TestLib
{

    public static class TestData
    {
        public static Faker<User> UserGenerator = new Faker<User>().Rules((faker, user) =>
            {
                var person = new Bogus.Person();
                user.Username = person.UserName;
                user.Email = person.Email;
                user.FirstName = person.FirstName;
                user.LastName = person.LastName;
                user.UserAddress = faker.Address.FullAddress();
                user.Status = faker.Random.Enum<Statuses>();
            }).RuleSet("FreeUsers", set =>
        {
            set.Rules((faker, user) =>
            {
                var person = new Bogus.Person();
                user.Username = person.UserName;
                user.Email = person.Email;
                user.FirstName = person.FirstName;
                user.LastName = person.LastName;
                user.UserAddress = faker.Address.FullAddress();
                user.Status = Statuses.Free;
            });
        }).RuleSet("DeactivatedUsers", set =>
        {
            set.Rules((faker, user) =>
            {
                var person = new Bogus.Person();
                user.Username = person.UserName;
                user.Email = string.Empty;
                user.FirstName = person.FirstName;
                user.LastName = person.LastName;
                user.UserAddress = faker.Address.FullAddress();
                user.Status = Statuses.Deactivated;
            });
        });

        public class TestClass
        {
            public void GenreateUsers(string ruleset = "default")
            {
                var user = TestData.UserGenerator.Generate();
                var userArray = TestData.UserGenerator.GenerateLazy(500).ToArray();
                var userList = TestData.UserGenerator.GenerateBetween(1, 5000).ToList();
                var freeUser = TestData.UserGenerator.Generate("FreeUsers");
                var deactivatedUser = TestData.UserGenerator.Generate("DeactivatedUser");
                var RulesetPassedInUser = TestData.UserGenerator.Generate(ruleset);
            }
        }

        public class User
        {
            public string Username;
            public string FirstName;
            public string LastName;
            public string UserAddress;
            public string Email;
            public Statuses Status;
        }

        public class Address
        {
        }
    }

    public enum Statuses
    {
        Paid,
        Free,
        Inactive,
        Deactivated
    }
}