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
using System.Text;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Reflection;

using Amazon.Runtime;
using Amazon.CognitoIdentityProvider.Model;

namespace Amazon.Extensions.CognitoAuthentication.Util
{
    internal static class CognitoAuthHelper
    {
        [ThreadStatic] private static SHA256 sha256;

        /// <summary>
        /// Property to access the thread-safe SHA256 member variable. 
        /// Creates a SHA256 instance if one does not exist.
        /// </summary>
        internal static SHA256 Sha256 => sha256 ?? (sha256 = SHA256.Create());

        /// <summary>
        /// Computes the secret hash for the user pool using the corresponding userID, clientID, 
        /// and client secret
        /// </summary>
        /// <param name="userID">The current userID</param>
        /// <param name="clientID">The clientID for the client being used</param>
        /// <param name="clientSecret">The client secret of the corresponding clientID</param>
        /// <returns>Returns the secret hash for the user pool using the corresponding 
        /// userID, clientID, and client secret</returns>
        public static string GetUserPoolSecretHash(string userID, string clientID, string clientSecret)
        {
            var message = userID + clientID;
            var keyBytes = Encoding.UTF8.GetBytes(clientSecret);
            var messageBytes = Encoding.UTF8.GetBytes(message);

            var hmacSha256 = new HMACSHA256(keyBytes);
            var hashMessage = hmacSha256.ComputeHash(messageBytes);

            return Convert.ToBase64String(hashMessage);
        }

        /// <summary>
        /// Creates a byte array which combines all of the byte[] in values in the order of the array
        /// </summary>
        /// <param name="values">An array of byte[] to be combined</param>
        /// <returns>Returns a byte array which combines all of the byte[] in values</returns>
        internal static byte[] CombineBytes(byte[][] values)
        {
            var combinedLength = 0;
            byte[] returnBytes;
            var copyIndex = 0;

            foreach (var t in values)
            {
                combinedLength += t.Length;
            }

            returnBytes = new byte[combinedLength];

            for (var i = 0; i < values.Length; i++)
            {
                Buffer.BlockCopy(values[i], 0, returnBytes, copyIndex, values[i].Length);
                copyIndex += values[i].Length;
            }

            return returnBytes;
        }

        /// <summary>
        /// Converts a hexadecimal string to a byte array
        /// </summary>
        /// <param name="hexString">The hexadecimal string to be converted to a byte array</param>
        /// <returns>Returns the byte array for the corresponding string</returns>
        internal static byte[] StringToByteArray(string hexString)
        {
            if(hexString.Length % 2 != 0)
            {
                throw new ArgumentException("Malformed hexString.", "hexString");
            }

            var stringLen = hexString.Length;
            var bytes = new byte[stringLen / 2];

            for (var i = 0; i < stringLen; i += 2)
            {
                bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            }

            return bytes;
        }

        /// <summary>
        /// Internal method to convert a dictionary of user attributes to a list of AttributeType
        /// </summary>
        /// <param name="attributeDict">Dictionary containing attributes of type string</param>
        /// <returns>Returns a List of AttributeType objects</returns>
        internal static List<AttributeType> CreateAttributeList(IDictionary<string, string> attributeDict)
        {
            var attributeList = new List<AttributeType>();
            foreach (var data in attributeDict)
            {
                var attribute = new AttributeType()
                {
                    Name = data.Key,
                    Value = data.Value
                };

                attributeList.Add(attribute);
            }
            return attributeList;
        }

        /// <summary>
        /// Internal method for handling metrics
        /// </summary>
        private const string UserAgentHeader = "User-Agent";
        internal static void ServiceClientBeforeRequestEvent(object sender, RequestEventArgs e)
        {
            if (!(e is WebServiceRequestEventArgs args) || !args.Headers.ContainsKey(UserAgentHeader))
                return;

            var metric = " AWSDotNetCognito/" + GetAssemblyFileVersion();
            if (!args.Headers[UserAgentHeader].Contains(metric))
            {
                args.Headers[UserAgentHeader] = args.Headers[UserAgentHeader] + metric;
            }
        }

        internal static string GetAssemblyFileVersion()
        {
            var assembly = typeof(CognitoAuthHelper).GetTypeInfo().Assembly;
            var attribute = assembly.GetCustomAttribute(typeof(AssemblyFileVersionAttribute)) as AssemblyFileVersionAttribute;
            return attribute == null ? "Unknown" : attribute.Version;
        }
    }
}
