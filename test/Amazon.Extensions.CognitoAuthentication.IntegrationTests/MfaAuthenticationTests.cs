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

using System;
using System.Collections.Generic;
using Xunit;

using Amazon.Runtime;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.CognitoAuthentication.Util;
using Amazon.IdentityManagement;
using Amazon.IdentityManagement.Model;

namespace Amazon.Extensions.CognitoAuthentication.IntegrationTests
{
    public class MfaAuthenticationTests : BaseAuthenticationTestClass
    {
        private readonly string policyArn;
        private string policyName;
        private readonly string roleArn;
        private readonly string roleName;

        //Tests MFA authentication flow
        [Fact]
        public async void TestMfaAuthenticationFlow()
        {
            var password = "PassWord1!";

            var context =
                await user.StartWithSrpAuthAsync(new InitiateSrpAuthRequest()
                {
                    Password = password
                }).ConfigureAwait(false);

            Assert.Equal(context.ChallengeName, ChallengeNameType.SMS_MFA);

           await Assert.ThrowsAsync<CodeMismatchException>(() => user.RespondToSmsMfaAuthAsync(new RespondToSmsMfaRequest()
           {
               MfaCode = "fakeMfaCode",
               SessionID = context.SessionID
           }));
        }

        /// <summary>
        /// Internal constructor to initialize a provider, user pool, and user for testing
        /// Created user info: Username = User 5, Password = PassWord1!, Email = xxx@yyy.zzz
        /// </summary>
        public MfaAuthenticationTests()
        {
            //Delete pool created by BaseAuthenticationTestClass
            if(pool != null)
            {
                provider.DeleteUserPoolAsync(new DeleteUserPoolRequest()
                {
                    UserPoolId = pool.PoolID
                }).Wait();
            }

            var passwordPolicy = new UserPoolPolicyType();
            var requiredAttributes = new List<SchemaAttributeType>();
            var verifiedAttributes = new List<string>();

            var creds = FallbackCredentialsFactory.GetCredentials();
            var region = FallbackRegionFactory.GetRegionEndpoint();

            provider = new AmazonCognitoIdentityProviderClient(creds, region);

            var adminCreateUser = new AdminCreateUserConfigType()
            {
                UnusedAccountValidityDays = 8,
                AllowAdminCreateUserOnly = false
            };

            passwordPolicy.PasswordPolicy = new PasswordPolicyType()
            {
                MinimumLength = 8,
                RequireNumbers = true,
                RequireSymbols = true,
                RequireUppercase = true,
                RequireLowercase = true
            };

            var emailSchema = new SchemaAttributeType()
            {
                Required = true,
                Name = CognitoConstants.UserAttrEmail,
                AttributeDataType = AttributeDataType.String
            };
            var phoneSchema = new SchemaAttributeType()
            {
                Required = true,
                Name = CognitoConstants.UserAttrPhoneNumber,
                AttributeDataType = AttributeDataType.String
            };
            requiredAttributes.Add(emailSchema);
            requiredAttributes.Add(phoneSchema);
            verifiedAttributes.Add(CognitoConstants.UserAttrEmail);
            verifiedAttributes.Add(CognitoConstants.UserAttrPhoneNumber);

            //Create Role for MFA
            using (var managementClient = new AmazonIdentityManagementServiceClient())
            {
                var roleResponse = managementClient.CreateRoleAsync(new CreateRoleRequest()
                {
                    RoleName = "TestRole_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"),
                    AssumeRolePolicyDocument = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow" +
                    "\",\"Principal\":{\"Service\":\"cognito-idp.amazonaws.com\"},\"Action\":\"sts:AssumeRole\",\"Condition" +
                    "\":{\"StringEquals\":{\"sts:ExternalId\":\"8327d096-57c0-4fb7-ad24-62ea8fc692c0\"}}}]}"
                }).Result;

                roleName = roleResponse.Role.RoleName;
                roleArn = roleResponse.Role.Arn;

                //Create and attach policy for role
                var createPolicyResponse = managementClient.CreatePolicyAsync(new CreatePolicyRequest()
                {
                    PolicyDocument = "{\"Version\": \"2012-10-17\",\"Statement\": [{\"Effect\": \"Allow\",\"Action" +
                    "\": [\"sns:publish\"],\"Resource\": [\"*\"]}]}",
                    PolicyName = "Cognito_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"),
                }).Result;

                policyName = createPolicyResponse.Policy.PolicyName;
                policyArn = createPolicyResponse.Policy.Arn;

                managementClient.AttachRolePolicyAsync(new AttachRolePolicyRequest()
                {
                    PolicyArn = policyArn,
                    RoleName = roleName
                }).Wait();
            }
           
            //Create user pool and client
            var createPoolRequest = new CreateUserPoolRequest
            {
                PoolName = "mfaTestPool_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"),
                Policies = passwordPolicy,
                Schema = requiredAttributes,
                AdminCreateUserConfig = adminCreateUser,
                MfaConfiguration = "ON",
                AutoVerifiedAttributes = verifiedAttributes,
                SmsConfiguration = new SmsConfigurationType
                {
                    SnsCallerArn = roleArn,
                    ExternalId = "8327d096-57c0-4fb7-ad24-62ea8fc692c0"
                }
            };

            //Build in buffer time for role/policy to be created
            CreateUserPoolResponse createPoolResponse = null;
            var bufferExMsg = "Role does not have a trust relationship allowing Cognito to assume the role";
            while (true)
            {
                try
                {
                    createPoolResponse = provider.CreateUserPoolAsync(createPoolRequest).Result;
                    break;
                }
                catch(Exception ex)
                {
                    if (string.Equals(bufferExMsg, ex.InnerException.Message))
                    {
                        System.Threading.Thread.Sleep(3000);
                    }
                    else
                    {
                        throw ex;
                    }
                }
             }

            var poolCreated = createPoolResponse.UserPool;

            var clientResponse = 
                provider.CreateUserPoolClientAsync(new CreateUserPoolClientRequest()
                {
                    ClientName = "App1",
                    UserPoolId = poolCreated.Id,
                    GenerateSecret = false,
                }).Result;

            var clientCreated = clientResponse.UserPoolClient;
            this.pool = new CognitoUserPool(poolCreated.Id, clientCreated.ClientId, provider, "");

            var signUpRequest = new SignUpRequest()
            {
                ClientId = clientCreated.ClientId,
                Password = "PassWord1!",
                Username = "User5",
                UserAttributes = new List<AttributeType>()
                {
                    new AttributeType() {Name=CognitoConstants.UserAttrEmail, Value="xxx@yyy.zzz"},
                    new AttributeType() {Name=CognitoConstants.UserAttrPhoneNumber, Value="+15555555555"}
                },
                ValidationData = new List<AttributeType>()
                {
                    new AttributeType() {Name=CognitoConstants.UserAttrEmail, Value="xxx@yyy.zzz"},
                    new AttributeType() {Name=CognitoConstants.UserAttrPhoneNumber, Value="+15555555555"}
                }
            };

            var signUpResponse = provider.SignUpAsync(signUpRequest).Result;

            var confirmRequest = new AdminConfirmSignUpRequest()
            {
                Username = "User5",
                UserPoolId = poolCreated.Id
            };
            var confirmResponse = provider.AdminConfirmSignUpAsync(confirmRequest).Result;

            this.user = new CognitoUser("User5", clientCreated.ClientId, pool, provider);
        }

        /// <summary>
        /// Internal method that cleans up the created user pool (along with associated client/user) 
        /// for testing
        /// </summary>
        public override void Dispose()
        {
            try
            {
                using (var client = new AmazonIdentityManagementServiceClient())
                {
                    client.DetachRolePolicyAsync(new DetachRolePolicyRequest()
                    {
                        PolicyArn = policyArn,
                        RoleName = roleName
                    }).Wait();

                    client.DeletePolicyAsync(new DeletePolicyRequest()
                    {
                        PolicyArn = policyArn
                    }).Wait();

                    client.DeleteRoleAsync(new DeleteRoleRequest()
                    {
                        RoleName = roleName
                    }).Wait();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine(ex.Message);
            }

            base.Dispose();
        }
    }
}
