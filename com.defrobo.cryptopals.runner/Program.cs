using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace com.defrobo.cryptopals.runner
{
    class Program
    {
        static void Main(string[] args)
        {
            var payload = "daniel.crowley.wilson@gmail.com";
            var encrypted = Crypto.EncryptProfileFor(payload);
            var output = Crypto.DecryptProfileFor(encrypted);
            foreach (var kvp in output)
            {
                Console.WriteLine("{0} = {1}", kvp.Key, kvp.Value);
            }
        }
    }
}
