﻿/*
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

using System;
using System.Threading.Tasks;
using System.Collections.Generic;
using Xunit;

using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication.Util;

namespace Amazon.Extensions.CognitoAuthentication.IntegrationTests
{
    public class AuthenticationSignUpUserTests : BaseAuthenticationTestClass
    {
        public AuthenticationSignUpUserTests() : base()
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
            user = new CognitoUser("User5", pool.ClientID, pool, provider);
        }

        // Tests the SignUp method (using random, dummy email)
        [Fact]
        public async Task TestSignUpProcess()
        {
            var userID = "User55";
            var password = "PassWord1!";
            var userAttributes = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { CognitoConstants.UserAttrEmail, "xxx@yyy.zzz"}
            };
            var validationData = new Dictionary<string, string>(StringComparer.Ordinal)
            {
                { CognitoConstants.UserAttrEmail, "xxx@yyy.zzz"}
            };

            await pool.SignUpAsync(userID, password, userAttributes, validationData).ConfigureAwait(false);

            var listUsersRequest = new ListUsersRequest()
            {
                Limit = 2,
                UserPoolId = pool.PoolID
            };
            var listUsersResponse = await provider.ListUsersAsync(listUsersRequest).ConfigureAwait(false);
            var containsUser55 = false;

            foreach (var user in listUsersResponse.Users)
            {
                if (string.Equals(user.Username, userID, StringComparison.Ordinal))
                {
                    containsUser55 = true;
                }
            }

            Assert.True(containsUser55);
        }

        // Tests that ConfirmSignUp reaches the proper failure point with incorrect confirmation code
        [Fact]
        public void TestConfirmSignUpFail()
        {
            Assert.ThrowsAsync<CodeMismatchException>(() => user.ConfirmSignUpAsync("fakeConfirmationCode", false));
        }
    }
}
