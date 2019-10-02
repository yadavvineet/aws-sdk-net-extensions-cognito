/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 * 
 *  http://aws.amazon.com/apache2.0
 * 
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

using System.Threading.Tasks;
using System.Collections.Generic;
using Xunit;

using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication.Util;

namespace Amazon.Extensions.CognitoAuthentication.IntegrationTests
{
    public class AuthenticationConfirmUserTests : BaseAuthenticationTestClass
    {
        public AuthenticationConfirmUserTests() : base()
        {
            var signUpRequest = new SignUpRequest()
            {
                ClientId = pool.ClientID,
                Password = "PassWord1!",
                Username = "User5",
                UserAttributes = new List<AttributeType>()
                {
                    new AttributeType() {Name=CognitoConstants.UserAttrEmail, Value="xxx@yyy.zzz"},
                },
                ValidationData = new List<AttributeType>()
                {
                   new AttributeType() {Name=CognitoConstants.UserAttrEmail, Value="xxx@yyy.zzz"}
                }
            };

            var signUpResponse = provider.SignUpAsync(signUpRequest).Result;

            var confirmRequest = new AdminConfirmSignUpRequest()
            {
                Username = "User5",
                UserPoolId = pool.PoolID
            };
            var confirmResponse = provider.AdminConfirmSignUpAsync(confirmRequest).Result;
            user = new CognitoUser("User5", pool.ClientID, pool, provider);
        }

        //Tests SRP authentication flow for web applications
        [Fact]
        public async void TestGenericSrpAuthentication()
        {
            var password = "PassWord1!";

            var context =
                await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
                {
                    Password = password
                }).ConfigureAwait(false);

            Assert.True(user.SessionTokens.IsValid());
        }

        // Tests the DeleteUser method
        [Fact]
        public async Task TestDeleteUser()
        {
            var userID = user.UserID;
            var users = new List<string>();

            var context =
                await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
                {
                    Password = "PassWord1!"
                }).ConfigureAwait(false);

            var listUsersRequest = new ListUsersRequest()
            {
                Limit = 60,
                UserPoolId = pool.PoolID
            };
            var listUsersReponse = await provider.ListUsersAsync(listUsersRequest).ConfigureAwait(false);
            foreach (var listUser in listUsersReponse.Users)
            {
                users.Add(listUser.Username);
            }

            Assert.Contains(userID, users);

            await user.DeleteUserAsync().ConfigureAwait(false);

            listUsersReponse = await provider.ListUsersAsync(listUsersRequest).ConfigureAwait(false);
            users.Clear();
            foreach(var listUser in listUsersReponse.Users)
            {
                users.Add(listUser.Username);
            }

            Assert.DoesNotContain(userID, users);
        }
    }
}
