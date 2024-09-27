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
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Extensions.CognitoAuthentication.Util;
using Xunit;

namespace CognitoAuthentication.UnitTests
{
    public class AuthenticationCryptoTests
    {
        // Tests the entire SRP protocol using the tactics from the class implementation
        [Fact]
        public void TestSrpProtocol()
        {
            // Choose hash algorithm, g, N, username, password, salt
            var sha256 = SHA256.Create();
            var g = AuthenticationHelper.g;
            var N = AuthenticationHelper.N;
            var password = "password";
            var saltString = "fef2871d83ce2120f9c47a46db303d37"; //Does not have to always be this string
            var salt = BigIntegerExtensions.FromUnsignedLittleEndianHex(saltString);

            // Compute x = H(s,p)
            var passBytes = Encoding.UTF8.GetBytes(password);
            var userIdHash = sha256.ComputeHash(passBytes);
            var saltBytes = salt.ToByteArray();
            var xBytes = new byte[saltBytes.Length + userIdHash.Length];
            Buffer.BlockCopy(saltBytes, 0, xBytes, 0, saltBytes.Length);
            Buffer.BlockCopy(userIdHash, 0, xBytes, saltBytes.Length, userIdHash.Length);
            var xDigest = sha256.ComputeHash(xBytes);
            var x = BigIntegerExtensions.FromUnsignedBigEndian(xDigest);

            // Compute v = g^x
            var v = BigInteger.ModPow(g, x, N);

            // Generate random a, b, A
            BigInteger a, b, A;
            do
            {
                a = AuthenticationHelper.CreateBigIntegerRandom();
                b = AuthenticationHelper.CreateBigIntegerRandom();
                A = BigInteger.ModPow(g, a, N);
            } while ((A.TrueMod(N)).Equals(BigInteger.Zero));

            // Calculate k = H(N, g)
            var nBytes = N.ToByteArray();
            var gBytes = g.ToByteArray();
            var content = new byte[nBytes.Length + gBytes.Length];
            Buffer.BlockCopy(nBytes, 0, content, 0, nBytes.Length);
            Buffer.BlockCopy(gBytes, 0, content, nBytes.Length, gBytes.Length);
            var digest = sha256.ComputeHash(content);
            var k = BigIntegerExtensions.FromUnsignedBigEndian(digest);

            //Calculate B = kv + g^b
            var B = k * v + (BigInteger.ModPow(g, b, N));

            // Calculate u = H(A,B)
            var ABytes = A.ToByteArray();
            var BBytes = B.ToByteArray();
            var ABcat = new byte[ABytes.Length + BBytes.Length];
            Buffer.BlockCopy(ABytes, 0, ABcat, 0, ABytes.Length);
            Buffer.BlockCopy(BBytes, 0, ABcat, ABytes.Length, BBytes.Length);
            var ABdigest = sha256.ComputeHash(ABcat);
            var u = BigIntegerExtensions.FromUnsignedBigEndian(ABdigest);

            // Calculate user side userS = (B - kg^x) ^ (a + ux)
            var userS = BigInteger.ModPow((B - k * BigInteger.ModPow(g, x, N)), a + u * x, N);

            // Calculate user side userK = H(userS)
            var userSBytes = userS.ToByteArray();
            var userSDigest = sha256.ComputeHash(userSBytes);
            var userK = BigIntegerExtensions.FromUnsignedBigEndian(userSDigest);

            // Calculate host side hostS = (Av^u) ^ b
            var hostS = BigInteger.ModPow((A * BigInteger.ModPow(v, u, N)), b, N);

            // Calculate host side hostK = H(hostS)
            var hostSBytes = hostS.ToByteArray();
            var hostSDigest = sha256.ComputeHash(hostSBytes);
            var hostK = BigIntegerExtensions.FromUnsignedBigEndian(hostSDigest);

            Assert.Equal(hostS, userS);
            Assert.Equal(hostK, userK);
        }

        // Checks that CreateTupleAa satisfies the SRP constraints
        [Fact]
        public void TestCreateTupleAa()
        {
            var tuple = AuthenticationHelper.CreateAaTuple();
            var A = tuple.Item1;
            var a = tuple.Item2;
            var g = AuthenticationHelper.g;

            Assert.Equal(A, BigInteger.ModPow(g, a, AuthenticationHelper.N));
            Assert.NotEqual(A.TrueMod(AuthenticationHelper.N), BigInteger.Zero);
        }

        // Using information from a known working claim, checks that authenticateUser correctly reproduces that claim
        [Fact]
        public void TestAuthenticateUser()
        {
            var username = "User5";
            var password = "Password1!";
            var poolName = "Pj8nlkpKR";
            var salt = "b704a27deb8cf5efec43a40eac5b60d2";
            var srpb = "f6c76f03232c3a93a634f5e49a74efbfffcd2b81f0dacb2bce0274ae68601b3d42a98feb96ba6a310cc2d4183edac62"
                + "d571d0d220258d8753a80c4f8815a10953a21964f19c824916f46417f46d921d7956bf5c10c63e7b1c84ce6e2bc407b4e0a103a52"
                + "9313f439182c6450ed434d049e0d9dd5da8cf3a1d1f6f2839f55754a7b17444b8c55ff6b13bf63f61e473ad6fad9f4a1a0b2541b2"
                + "00de07c10296d679b36bf683245cee039842ad9579031e26cb0931ac202fe713fa2c64f920a9830722f708d5ede7ab0521363e45f"
                + "b2ad0afefbd65264c39f46d0c4011e2e8dbf8d6c53764719599a359b17bcd4d7e37c76e9e68adde0dc586a29f835a2decab335a49"
                + "408fbc8452d2696743f4465d12748851889d405d7287296e93f9abfb9f11806235bb588e8381a0060a174f5b0959eedba81b94eb3"
                + "83e80465323b1fc85478edcca4b67403a45b73ccbdcd9eaeacebd5f2ca32c7344fdbbc15a2a3d060c2b822851a282370a8dacbbfe"
                + "dbc511376a6e8ad95a5ce28fc2b9c37751c8d4314b9";
            var secretBlock = "iZY+s7lYj4/5me1dgBZ9QR0vYOoatfBhec3Rc3kqPFAGIWAwxmaoXkOR1+kEvm0Aic/CxgXe0KHTTZuyKpsMfjbo2"
                + "J2YweeAtj47z6HCgVScBHeJ5il4NUhGJ6ehqWPls5ub233161UU/SxKAZYySbB8NNHIQidPNxEvBycU5gOeO9cOv4dlm3dwSRNFlg8OWJ"
                + "ysI7+ZXUgSWdfUBqog90wkIfLr7HirXnd3axiqpHqAApu4Ls7JFvgXxJa74ZJLtFobED/qSc4ALtRiAPwhKkomxhSXDF1S3dD+LcTQaR0"
                + "/gJY1+p1CuyTCQNBTVz5idOq8NhG/mMupKow7i54xWJp3gWCeRLMRYD5Od/b7QSgtBYZeLT2rDPb6T8oy8qScK4gq+1Ye6KmXTtmdc7XB"
                + "hwtyCk4xA8YBjeXO/Gq3G+rzpqMOS9e8P/EZ1xldkcme0qYesbUiKSVO30N2lPKo3qzWyq6zFi0pINpCiWLD+qdWa9Arofsml2IYgCxZw"
                + "moIRVk8vd/+UdhErVRFdOmMZWQVLki0K09UgrnvLLBcMxc4wq8myUmMivVpxg8vSaexrxGxDVnKZHgfl0jFCEWIYyMvPAspOo9bBT1l+o"
                + "QlVpf6RPKWlxgE4JSiWd9LD3PMdtETsyrWv1IxtktyzGI27UVanj0gGfesM56/FNImaxh+eoTBq4fJWxvfN0FvB90Ib/ZV+oJZ3jj8pKr"
                + "ZmDohutOQZqEIP5mme3UMGbkeF1zVnBuPT/Ujyb94RayMB4qvqnZap87o8gJ4iv0yp+HMAAxvPSvYJSr/dny/jEdsWM8aKU+a9+n3aMPo"
                + "/97DSIyiw2E3jcorR2emlichUHqdwDg/GAACUMTmV6peecDdhuF/KNZXBF4GEsoutDzPSsaXnQ11qKejULZt//fQ/e5JzWbUVhWXBOiRr"
                + "4JmbPdmWo9WIORrg/yrAlSe9RNnJOW+OCsAKLZYEHfuueUQYaxOpBTst+YQXzbwNYyX47H8nUDVXRLiA0zAoQHeTMXN8lL688MTICEUNa"
                + "JW9QWjrNIaTPic0oJ6CxVM/ayd8qv28EQ9BhyyE5yEreC9y+bpUQjTwxe62H/j0NiMsE5806dhx2RzxBlEYl51hs1aqwpQ6NGn51bwZPZ"
                + "5O7YitLyYdAoEdTo0hCXTKF2ITbSy8ZDv5cxQSv5zyXeHRfa/o1GSHWPawy3lYjHChVVj/ALBjpFVPJJwByQZqgXsrvuknWk7QFAi21ac"
                + "Qxm/4pqPVtFNVW7yZ51FawlQu6rKKfu1kyTJ6CKlcdXuJFv/NxQLPLq/to4b0UHNaD/mymwr0GSEn9GxpVB4fjhL4L2BRxCpt4lfLtx1K"
                + "MiTivUMIhrVShnrgUy2mpd/jooMsSf17GSvCYReg9dsaqvZXqbEMv6P2BX+RNXicLSfeDO9NyZhtuWZxyLJ5IlagOpVNbtGb/HCEQy+zF"
                + "8ySzho6e8vHxNodJX+xwCxRyKl6wbEdSEulWgm5WaUmsfySrNqLKassfrTdKLHyWUvjbWucEFzS0ddu+Q7j5RGaZ4MO7Qf1hN57WUE7ir"
                + "wXBc9UoAWI3Sggb+oDDuVKN5PMF6cL+3/yfetGX0Wrh9tk34z5pizLmOgqOqkMW5yFDqw8/pRqQA4Qo+VrpHL1a4vANgmOHw98918pFiC"
                + "G5lacOQn4FmA2QGWfNxU72qy6MLPnTgN/olShAFNFgckIn2F";
            var timeStr = "Thu Jun 15 07:00:00 UTC 2017";

            var bytes = new byte[1024];
            for (var i = bytes.Length - 1; i > 0; i--)
            { bytes[i] = 2; }
            var a = new BigInteger(bytes);
            var A = BigInteger.ModPow(AuthenticationHelper.g, a, AuthenticationHelper.N);
            var tupleAa = Tuple.Create<BigInteger, BigInteger>(A, a);

            var claim = AuthenticationHelper.AuthenticateUser(username, password, poolName,
                tupleAa, salt, srpb, secretBlock, timeStr);
            var claimBase64 = Convert.ToBase64String(claim);
            var correctClaim = "QwHbbUqF6DSSepJh2QqTWDCb1XjmqaxnnW5kDn5dz7E=";

            Assert.Equal(correctClaim, claimBase64);
        }

        // Using infromation from a known working claim, checks that getPasswordAuthenticationKey generates the correct key
        [Fact]
        public void TestGetPasswordAuthenticationKey()
        {
            var username = "User5";
            var password = "Password1!";
            var poolName = "Pj8nlkpKR";
            var bytes = new byte[1024];
            for (var i = bytes.Length - 1; i > 0; i--)
            { bytes[i] = 2; }
            var a = new BigInteger(bytes);
            var A = BigInteger.ModPow(AuthenticationHelper.g, a, AuthenticationHelper.N);
            var tupleAa = Tuple.Create<BigInteger, BigInteger>(A, a);
            var srpb = "8d340308265ada665b1b2c730fb65ff0b6dc746b63c2d7e9f08b8aa9306d4848268bc0c17ee4a2999173ca62af59fd74b"
                + "a5d00f16c96bea082b163f2c3a0b745455d62cb9577425b4b5d4dadba163a8e7759a7c0256795f464682770588c84e82f2c63d47017"
                + "51476da8e8a7b1a131e78560fe7b56b6761fcef88dcc486f403369a0cac2f04c25ed6d5e08b5a2f488500a0d5af4972cfa1213bfca3"
                + "7bbae189c8d58465b13193204f21ea01d267c7688e6e6cb5d3f5a8005db680d272308ee823816032dd2c8fc3b95b6fd0a742feb127e"
                + "3d094cd002a5e6b209415ff82f6abf50d5da43910a0336e9a6fc33dd101bf13f22f13fcb3ea3809aae4917d7c426fb8c0a894030c75"
                + "d3e15f0e1078a9d89e5154391cde6111ac14fab9fa3b3a880da7dbd47fd5a055937581d26b5d225c076e82f980dcbd77b3950d270d8"
                + "b622dca9c9bcd8fd6435a59b9690b3c9e2bdabf58cae3420c19066abc420145b1b66f226a6493c96588c2d53b637798fcaa573379f2"
                + "251848065fe1fafb68ed5e79135e9";
            var B = BigIntegerExtensions.FromUnsignedLittleEndianHex(srpb);
            var salt = BigIntegerExtensions.FromUnsignedLittleEndianHex("b704a27deb8cf5efec43a40eac5b60d2");

            var key = AuthenticationHelper.GetPasswordAuthenticationKey(username, password, poolName, tupleAa, B, salt);
            var testKey = Convert.ToBase64String(key);
            var correctKey = "LmbBsy/4chqMRYOhmtmCrA==";

            Assert.Equal(correctKey, testKey);
        }

        // Checks the secret hashing algoithm from the CognitoSecretHash class
        [Fact]
        public void TestSecretHash()
        {
            var hash = CognitoAuthHelper.GetUserPoolSecretHash("Mess", "age", "secret");

            Assert.Equal("qnR8UCqJggD55PohusaBNviGoOJ67HC6Btry4qXLVZc=", hash);
        }

        // Using infromation from a known working claim, checks GetUserIdHash method from CognitoDeviceHelper
        [Fact]
        public void TestGetDeviceKeyHash()
        {
            var deviceGroupKey = "Pj8nlkpKR";
            var deviceKey = "User5";
            var password = "Password1!";

            var key = CognitoDeviceHelper.GetDeviceKeyHash(deviceGroupKey, deviceKey, password);
            var testKey = Convert.ToBase64String(key);
            var correctKey = "rJra60Rbj/4QW4UdYVl7wde78eMoiaw7Wk+WoDqo5K8=";

            Assert.Equal(correctKey, testKey);
        }

        //HKDF Test Vector 1
        [Fact]
        public void TestHkdfVector1()
        {
            // Expected Values
            var prkFromSepc = CognitoAuthHelper.StringToByteArray("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3" +
                "122ec844ad7c2b3e5");
            var okmFromSpec = CognitoAuthHelper.StringToByteArray("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4" +
                "c5db02d56ecc4c5bf34007208d5b887185865");

            var ikmBytes = CognitoAuthHelper.StringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var saltBytes = CognitoAuthHelper.StringToByteArray("000102030405060708090a0b0c");
            var infoBytes = CognitoAuthHelper.StringToByteArray("f0f1f2f3f4f5f6f7f8f9");
            var length = 42;

            var hkdfSha256 = new HkdfSha256(saltBytes, ikmBytes);
            var hkdfResult = hkdfSha256.Expand(infoBytes, length);

            Assert.Equal(prkFromSepc, hkdfSha256.Prk);
            Assert.Equal(okmFromSpec, hkdfResult);
        }

        //HKDF Test Vector 2
        [Fact]
        public void TestHkdfVector2()
        {
            // Expected Values
            var prkFromSpec = CognitoAuthHelper.StringToByteArray("06a6b88c5853361a06104c9ceb35b45cef760014904671" +
                "014a193f40c15fc244");
            var okmFromSpec = CognitoAuthHelper.StringToByteArray("b11e398dc80327a1c8e7f78c596a49344f012eda2d4efa" +
                "d8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71c" +
                "c30c58179ec3e87c14c01d5c1f3434f1d87");

            var ikmBytes = CognitoAuthHelper.StringToByteArray("000102030405060708090a0b0c0d0e0f101112131" +
                "415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d" +
                "3e3f404142434445464748494a4b4c4d4e4f");
            var saltBytes = CognitoAuthHelper.StringToByteArray("606162636465666768696a6b6c6d6e6f70717273" +
                "7475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9" +
                "d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
            var infoBytes = CognitoAuthHelper.StringToByteArray("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3" +
                "c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebece" +
                "deeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            var length = 82;

            var hkdfSha256 = new HkdfSha256(saltBytes, ikmBytes);
            var hkdfResult = hkdfSha256.Expand(infoBytes, length);

            Assert.Equal(prkFromSpec, hkdfSha256.Prk);
            Assert.Equal(okmFromSpec, hkdfResult);
        }

        //HKDF Test Vector 3
        [Fact]
        public void TestHkdfVector3()
        {
            // Expected Values
            var prkFromSpec = CognitoAuthHelper.StringToByteArray("19ef24a32c717b167f33a91d6f648bdf96596776afdb6" +
                "377ac434c1c293ccb04");
            var okmFromSpec = CognitoAuthHelper.StringToByteArray("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee18" +
                "79ec3454e5f3c738d2d9d201395faa4b61a96c8");

            var ikmBytes = CognitoAuthHelper.StringToByteArray("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var saltBytes = CognitoAuthHelper.StringToByteArray("");
            var infoBytes = CognitoAuthHelper.StringToByteArray("");
            var length = 42;

            var hkdfSha256 = new HkdfSha256(saltBytes, ikmBytes);
            var hkdfResult = hkdfSha256.Expand(infoBytes, length);

            Assert.Equal(prkFromSpec, hkdfSha256.Prk);
            Assert.Equal(okmFromSpec, hkdfResult);
        }
    }
}