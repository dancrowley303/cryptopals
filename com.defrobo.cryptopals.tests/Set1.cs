using NUnit.Framework;
using System.Linq;
using System.Text;

namespace com.defrobo.cryptopals.tests
{
    [TestFixture]
    public class Set1
    {
        [Test]
        public void Challenge1()
        {
            string result = Crypto.HexStringToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
            Assert.AreEqual("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", result);
        }

        [Test]
        public void Challenge2()
        {
            byte[] left = Crypto.HexStringToByteArray("1c0111001f010100061a024b53535009181c");
            byte[] right = Crypto.HexStringToByteArray("686974207468652062756c6c277320657965");
            var result = Crypto.FixedXOR(left, right);
            Assert.AreEqual("the kid don't play", Encoding.UTF8.GetString(result));
        }

        [Test]
        public void Challenge3()
        {
            var candidates = Crypto.BuildXORCipherRangeForScoring(
                Crypto.HexStringToByteArray(
                    "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"));
            var bestScore = Crypto.ScoreCryptograms(candidates);
            Assert.AreEqual("Cooking MC's like a pound of bacon", bestScore);
        }
    }
}
