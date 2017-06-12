﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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

        public static T[][] SplitIntoMatrix<T>(this T[] input, int size)
        {
            var output = new List<T[]>();
            for (var i = 0; i < input.Length; i += size)
            {
                var sizeToCopy = Math.Min(input.Length - i, size);
                var newSegment = new T[size];
                Array.Copy(input, i, newSegment, 0, sizeToCopy);
                output.Add(newSegment);
            }
            return output.ToArray();
        }

        public static T[][] Transpose<T>(this T[][] input, int keySize)
        {
            var output = new List<T[]>();
            for (var i = 0; i < keySize; i++)
            {
                var segment = new T[input.Length];
                for (var j = 0; j < input.Length; j++)
                {
                    segment[j] = input[j][i];
                }
                output.Add(segment);
            }
            return output.ToArray();
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

        public static Dictionary<char, byte[]> BuildXORCipherRangeForScoring(byte[] input)
        {
            var xored = new Dictionary<char, byte[]>();
            for (char i = ' '; i <= '~'; i++)
            {
                xored.Add(i, SingleByteXORCipher(i, input));
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

        public static byte[] BreakRepeatingKeyXOR(byte[] input)
        {
            var keySize = FindLowestNormalizedEditDistanceKeySize(input);
            var transposed = input.SplitIntoMatrix(keySize).Transpose(keySize);
            var key = FindVignereKey(transposed, keySize);
            return EncryptRepeatingKeyXOR(key, input);
        }

        private static byte[] FindVignereKey(byte[][] transposed, int keySize)
        {
            var key = new byte[keySize];

            for (var i = 0; i < transposed.Length; i++)
            {
                var candidates = BuildXORCipherRangeForScoring(transposed[i]);
                var bestChar = '\0';
                var bestScore = 0m;
                foreach(var candidate in candidates)
                {
                    var score = ScoreEnglishFrequency(candidate.Value);
                    if (score > bestScore)
                    {
                        bestScore = score;
                        bestChar = candidate.Key;
                    }
                }
                key[i] = (byte)bestChar;
            }
            return key;
        }

        private static int FindLowestNormalizedEditDistanceKeySize(byte[] input)
        {
            var lowestKeySize = 0;
            var lowestNormalizedEditDistance = Decimal.MaxValue;

            for (var keySize = 2; keySize <= 40; keySize++)
            {
                var calculationCount = 0;
                var hammingDistance = 0;
                //Crptopals says you can just look at the first couple of blocks, but I needed to
                //average every block to get meaningful calcs
                for (var i = 1; i < input.Length / keySize; i++)
                {
                    var left = new ArraySegment<byte>(input, keySize * (i - 1), keySize).ToArray();
                    var right = new ArraySegment<byte>(input, keySize * i, keySize).ToArray();
                    hammingDistance += HammingDistance(left, right);
                    calculationCount++;
                }
                var normalizedEditDistance = (decimal)hammingDistance / (decimal)calculationCount / (decimal)keySize;
                if (normalizedEditDistance < lowestNormalizedEditDistance)
                {
                    lowestNormalizedEditDistance = normalizedEditDistance;
                    lowestKeySize = keySize;
                }
            }
            return lowestKeySize;
        }

        public static int HammingDistance(byte[] left, byte[] right)
        {
            if (left.Length != right.Length)
                throw new ArgumentException("left and right parameters must be same length");

            var score = 0;

            for (var i = 0; i < left.Length; i++)
            {
                var distance = 0;
                var val = left[i] ^ right[i];
                while (val != 0)
                {
                    distance++;
                    //this clears the lowest order nonzero bit
                    val &= val - 1;
                }
                score += distance;
            }
            return score;
        }

        public static string PrettyPrintHex(byte[] input)
        {
            var sb = new StringBuilder(input.Length * 2);
            for (var i = 0; i < input.Length; i++)
            {
                sb.AppendFormat("{0:x2}", input[i]);
            }
            return sb.ToString();
        }

        public static byte[] EncryptRepeatingKeyXOR(byte[] key, byte[] input)
        {
            var keyLength = key.Length;
            var output = new byte[input.Length];
            for (var i = 0; i < input.Length; i++)
            {
                output[i] = (byte)(input[i] ^ key[i % keyLength]);
            }
            return output;
        }

        public static byte[] HexStringToByteArray(string input)
        {
            return input.SplitInParts(2)
                 .Select(s => (byte)Convert.ToInt32(s, 16))
                 .ToArray();        
        }
    }
}
