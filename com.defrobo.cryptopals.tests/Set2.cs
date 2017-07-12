using NUnit.Framework;
using System;
using System.IO;
using System.Text;

namespace com.defrobo.cryptopals.tests
{
    [TestFixture]
    public class Set2
    {
        [Test]
        public void Challenge9()
        {
            var input = Encoding.ASCII.GetBytes("YELLOW SUBMARINE");
            var output = Crypto.BlockPad(input, 20);
            Assert.AreEqual("YELLOW SUBMARINE\x04\x04\x04\x04", Encoding.ASCII.GetChars(output));
        }

        [Test]
        public void Challenge10()
        {
            var encrypted = Convert.FromBase64String(File.ReadAllText(TestContext.CurrentContext.TestDirectory + "\\resources\\10.txt"));
            var key = Encoding.UTF8.GetBytes("YELLOW SUBMARINE");
            var iv = Encoding.UTF8.GetBytes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");
            var output = Encoding.UTF8.GetString(AES128.DecryptCBC(encrypted, key, iv));
            Assert.IsTrue(output.StartsWith("I'm back and I'm ringin' the bell"));
        }

        [Test]
        public void Challenge11()
        {
            bool isECB;
            var input = Encoding.UTF8.GetBytes("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE");
            var output = Crypto.AESEncryptionOracle(input, out isECB);
            var detectedECB = Crypto.ECBDetectionOracle(output);
            Assert.AreEqual(isECB, detectedECB);
        }

        [Test]
        public void Challenge12()
        {
            var plaintext = Crypto.ByteAtATimeECBDecryption(simple: true);
            var expected = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n";
            Assert.AreEqual(expected, plaintext);
        }

        [Test]
        public void Challenge13()
        {
            var payload = "xyz12@xyz.admin\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000b\u000bcom";
            var encrypted = Crypto.EncryptProfileFor(payload);
            var rearrange = new byte[48];
            Array.Copy(encrypted, 0, rearrange, 0, 16);
            Array.Copy(encrypted, 32, rearrange, 16, 16);
            Array.Copy(encrypted, 16, rearrange, 32, 16);

            var output = Crypto.DecryptProfileFor(rearrange);
            Assert.AreEqual("xyz12@xyz.com", output["email"]);
            Assert.AreEqual("admin", output["role"]);
        }

        [Test]
        public void Challenge14()
        {
            var plaintext = Crypto.ByteAtATimeECBDecryption(simple: false);
            var expected = "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n";
            Assert.AreEqual(expected, plaintext);
        }

    }
}
