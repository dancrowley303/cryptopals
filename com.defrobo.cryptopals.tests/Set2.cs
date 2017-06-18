using NUnit.Framework;
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
    }
}
