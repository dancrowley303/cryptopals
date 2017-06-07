using System;
using System.Collections.Generic;
using System.Linq;

namespace com.defrobo.cryptopals
{
    public static class Crypto
    {
        public static IEnumerable<String> SplitInParts(this String s, int partLength)
        {
            for (var i = 0; i < s.Length; i+=partLength)
            {
                yield return s.Substring(i, Math.Min(partLength, s.Length - i));
            }
        }

        public static byte[] FixedXOR(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
                throw new ArgumentException("left and right parameters must be the same length");

            var xored = new byte[left.Length];
            for (var i = 0; i < left.Length; i++)
            {
                xored[i] = (byte)(left[i] ^ right[i]);
            }
            return xored;
        }

        public static string HexStringToBase64(string input)
        {
            var hexSplit = HexStringToByteArray(input);
            return Convert.ToBase64String(hexSplit);
        }

        public static List<byte[]> BuildXORCipherRangeForScoring(byte[] input)
        {
            var xored = new List<byte[]>();
            for (char i = ' '; i <= '~'; i++)
            {
                xored.Add(SingleByteXORCipher(i, input));
            }
            return xored;
        }

        private static byte[] SingleByteXORCipher(char xorKey, byte[] input)
        {
            var output = new byte[input.Length];
            for (var i = 0; i < input.Length; i++)
            {
                output[i] = (byte)(input[i] ^ xorKey);
            }
            return output;
        }

        public static byte[] ScoreCryptograms(IEnumerable<byte[]> input)
        {
            return input.Aggregate((agg, next) => ScoreEnglishFrequency(next) > ScoreEnglishFrequency(agg) ? next : agg);
        }

        private static decimal ScoreEnglishFrequency(byte[] input)
        {
            var tempScore = 0;
            return input.Select<byte, int>(i =>
            {
                frequencies.TryGetValue((char)i, out tempScore);
                return tempScore;
            }).Sum() / input.Length;
        }

        //caching a static instance as it's used in lots of lookups
        private static Dictionary<char, int> frequencies = new Dictionary<char, int>
        {
            ['e'] = 26,
            ['t'] = 25,
            ['a'] = 24,
            ['o'] = 23,
            ['i'] = 22,
            ['n'] = 21,
            ['s'] = 20,
            ['h'] = 19,
            ['r'] = 18,
            ['d'] = 17,
            ['l'] = 16,
            ['c'] = 15,
            ['u'] = 14,
            ['m'] = 13,
            ['w'] = 12,
            ['f'] = 11,
            ['g'] = 10,
            ['y'] = 9,
            ['p'] = 8,
            ['b'] = 7,
            ['v'] = 6,
            ['k'] = 5,
            ['j'] = 4,
            ['x'] = 3,
            ['q'] = 2,
            ['z'] = 1
        };

        public static byte[] HexStringToByteArray(string input)
        {
            return input.SplitInParts(2)
                 .Select(s => (byte)Convert.ToInt32(s, 16))
                 .ToArray();        
        }
    }
}
