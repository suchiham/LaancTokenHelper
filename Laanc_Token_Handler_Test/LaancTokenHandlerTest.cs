using Laanc_Token_Handler;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using System.Linq;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Cryptography;
using System;

namespace Laanc_Token_Handler_Test
{
    public class Tests
    {

        LaancTokenHandler laancTokenHandler;
        [SetUp]
        public void Setup()
        {
            laancTokenHandler = new LaancTokenHandler();
        }


        [Test]
        public void TestDeactivatedKey()
        {

            //break point at server call to test, 

            //No Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);

            try
            {
                //should break at server point
                laancTokenHandler.GetJWKByKID("testKID3");

                //should fail and threw exception
                Assert.Fail();
                
            }
            catch { 

            }

            //NO Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);

        }
        [Test]
        public void TestGetCachedKey()
        {

            //break point at server call to test, 

            //No Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);

            //should break at server point
            laancTokenHandler.GetJWKByKID("testKID1");

            //1 Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 1);

            //should not break at server point
            laancTokenHandler.GetJWKByKID("testKID1");
            laancTokenHandler.GetJWKByKID("testKID1");
            laancTokenHandler.GetJWKByKID("testKID1");
            laancTokenHandler.GetJWKByKID("testKID1");
            laancTokenHandler.GetJWKByKID("testKID1");
            laancTokenHandler.GetJWKByKID("testKID1");

            //1 Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 1);

        }

        [Test]
        public void TestRetriveJWKComplex()
        {
            //No Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);

            //Retriving one good key and validate cached key count
            JsonWebKey jwt1 = laancTokenHandler.RetriveFAAJWTKromServer("testKID1");
            Assert.IsNotNull(jwt1);
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 1);

            //Retriving another good key and validate cached key count
            JsonWebKey jwt2 = laancTokenHandler.RetriveFAAJWTKromServer("testKID2");
            Assert.IsNotNull(jwt2);
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 2);

            //Retriving one duplicate key and validate cached key count
            try
            {
                JsonWebKey duplicatedkey = laancTokenHandler.RetriveFAAJWTKromServer("testKID1");
                Assert.Fail();
            }
            catch
            {
            }

            //Retriving one bad key and validate cached key count
            try
            {
                JsonWebKey passcase = laancTokenHandler.RetriveFAAJWTKromServer("testKID3");
                Assert.Fail();
            }
            catch
            {
            }

            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 2);
        }
        [Test]
        public void TestRetriveDuplicateJWK()
        {
            //No Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);

            //Retriving one good key and validate cached key count
            JsonWebKey passcase = laancTokenHandler.RetriveFAAJWTKromServer("testKID1");
            Assert.IsNotNull(passcase);
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 1);

            //Retriving one duplicate key and validate cached key count
            try
            {
                JsonWebKey duplicatedkey = laancTokenHandler.RetriveFAAJWTKromServer("testKID1");
                Assert.Fail();
            }
            catch
            {
            }

            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 1);
        }
        [Test]
        public void TestRetriveDisabledJWK()
        {
            //No Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);

            //Retriving one bad key and validate cached key count
            try
            {
                JsonWebKey passcase = laancTokenHandler.RetriveFAAJWTKromServer("testKID3");
                Assert.Fail();
            }
            catch { 
            }

            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);
        }
        [Test]
        public void TestRetriveGoodJWK()
        {
            //No Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);

            //Retriving one good key and validate cached key count
            JsonWebKey passcase =  laancTokenHandler.RetriveFAAJWTKromServer("testKID1");
            Assert.IsNotNull(passcase);
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 1);
        }

        [Test]
        public void TestGetKidFromGoodKey() {
            string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3RLSUQxIn0.eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyNX0.LldspT4kwMbG5EqhD0fXkrkehzRRRewlglfZd9Dt5S4";
            string kid  = laancTokenHandler.GetKIDByJWT(jwt);

            Assert.AreEqual(kid, "testKID1");
        }

        [Test]
        public void TestGetKidFromKeyWithNoKid()
        {
            string jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTUxNjIzOTAyNX0.WE74bh0TQDQOgu4TUtQ7SsxrQk4MdLbva8JBbfcWgEY";

            try
            {
                string kid = laancTokenHandler.GetKIDByJWT(jwt);
                Assert.Fail();
            }
            catch
            { 
            }
        }


        [Test]
        public void TestValidateToken()
        {
            //NO Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 0);

            string sampleJWT = "eyJraWQiOiIxZTlnZGs3IiwiYWxnIjoiUlMyNTYifQ.ewogImlzcyI6ICJodHRwOi8vc2VydmVyLmV4YW1wbGUuY29tIiwKICJzdWIiOiAiMjQ4Mjg5NzYxMDAxIiwKICJhdWQiOiAiczZCaGRSa3F0MyIsCiAibm9uY2UiOiAibi0wUzZfV3pBMk1qIiwKICJleHAiOiAxMzExMjgxOTcwLAogImlhdCI6IDEzMTEyODA5NzAsCiAiY19oYXNoIjogIkxEa3RLZG9RYWszUGswY25YeENsdEEiCn0.XW6uhdrkBgcGx6zVIrCiROpWURs-4goO1sKA4m9jhJIImiGg5muPUcNegx6sSv43c5DSn37sxCRrDZZm4ZPBKKgtYASMcE20SDgvYJdJS0cyuFw7Ijp_7WnIjcrl6B5cmoM6ylCvsLMwkoQAxVublMwH10oAxjzD6NEFsu9nipkszWhsPePf_rM4eMpkmCbTzume-fzZIi5VjdWGGEmzTg32h3jiex-r5WTHbj-u5HL7u_KP3rmbdYNzlzd1xWRYTUs4E8nOTgzAUwvwXkIQhOh5TPcSMBYy6X3E7-_gr9Ue6n4ND7hTFhtjYs3cjNKIA08qm5cpVYFMFMG6PkhzLQ";

            var isValid = laancTokenHandler.ValidateToken(sampleJWT);
            Assert.IsTrue(isValid);

            //NO Keys 
            Assert.AreEqual(laancTokenHandler.CachedLaancJWKs.Keys.Count, 1);

            //Hitting Cached Keys
            for (int i = 0; i < 1000; i++)
            {
                Assert.IsTrue(laancTokenHandler.ValidateToken(sampleJWT));
            }
          
        }


    }
}