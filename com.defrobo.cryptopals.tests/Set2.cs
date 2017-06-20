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
    }
}
