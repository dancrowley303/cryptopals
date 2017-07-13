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
            var payload = ":admin<true";
            var encrypted = Crypto.CBCBitflipOracle(payload);
            encrypted[16] ^= 0x01;
            encrypted[22] ^= 0x01;
            Console.WriteLine(Crypto.IsAdmin(encrypted));
        }
    }
} 
