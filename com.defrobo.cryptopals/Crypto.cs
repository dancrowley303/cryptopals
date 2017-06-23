using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace com.defrobo.cryptopals
{
    public static partial class Crypto
    {
        private static Random random = new Random(DateTime.Now.Millisecond);

        public static byte[] BlockPad(byte[] input, int blockSize)
        {
            var output = new byte[blockSize];
            if (input.Length == blockSize)
                Array.Copy(input, output, blockSize);
            else
            {
                //ignores cases where block length is larger than requested block size
                Array.Copy(input, output, input.Length);
                int padding = blockSize - input.Length;
                for (int i = 0; i < padding; i++)
                {
                    output[input.Length + i] = (byte)padding;
                }
            }
            return output;
        }

        //rawInput is a collection of hex strings
        public static string DetectAESInECBMode(string[] rawInput)
        {
            var lowestKeyCount = int.MaxValue;
            var lowestKeyCountKey = "";

            foreach (var line in rawInput)
            {
                var bytes = HexStringToByteArray(line);
                var scoreCount = new Dictionary<string, int>();
                for (var i = 0; i < bytes.Length; i += 16)
                {
                    var block = new ArraySegment<byte>(bytes, i, 16).ToArray();
                    var key = PrettyPrintHex(block);
                    if (!scoreCount.ContainsKey(key))
                        scoreCount[key] = 1;
                    else
                        scoreCount[key]++;
                }
                if (scoreCount.Keys.Count < lowestKeyCount)
                {
                    lowestKeyCount = scoreCount.Keys.Count;
                    lowestKeyCountKey = line;
                }
            }
            return lowestKeyCountKey;
        }

        public static void ShiftLeft<T>(this T[] block, int shift)
        {
            //stops overhead if shifts > block length
            shift = shift % block.Length;

            var buffer = new T[shift];
            Array.Copy(block, buffer, shift);
            Array.Copy(block, shift, block, 0, block.Length - shift);
            Array.Copy(buffer, 0, block, block.Length - shift, shift);
        }

        public static void ShiftRight<T>(this T[] block, int shift)
        {
            //stops overhead if shifts > block length
            shift = shift % block.Length;

            var buffer = new byte[shift];
            Array.Copy(block, block.Length - shift, buffer, 0, shift);
            Array.Copy(block, 0, block, shift, block.Length - shift);
            Array.Copy(buffer, 0, block, 0, shift);
        }

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

        public static byte[] RandomAES128Key()
        {
            var buffer = new byte[16];
            random.NextBytes(buffer);
            return buffer;
        }

        public static byte[] AESEncryptionOracle(byte[] input, out bool isECB)
        {
            var randomKey = RandomAES128Key();

            var randomPrefixLength = random.Next(5, 11);
            var randomPrefixBuffer = new byte[randomPrefixLength];
            random.NextBytes(randomPrefixBuffer);

            var randomSuffixLength = random.Next(5, 11);
            var randomSuffixBuffer = new byte[randomSuffixLength];
            random.NextBytes(randomSuffixBuffer);

            var paddedInput = new byte[randomPrefixLength + input.Length + randomSuffixLength];
            Array.Copy(randomPrefixBuffer, 0, paddedInput, 0, randomPrefixLength);
            Array.Copy(input, 0, paddedInput, randomPrefixLength, input.Length);
            Array.Copy(randomSuffixBuffer, 0, paddedInput, randomPrefixLength + input.Length, randomSuffixLength);

            if (paddedInput.Length % 16 != 0)
            {
                paddedInput = BlockPad(paddedInput, paddedInput.Length + (16 - paddedInput.Length % 16));
            }

            isECB = random.Next(0, 2) == 1;

            if (isECB)
            {
                return AES128.EncryptECB(paddedInput, randomKey);
            } else
            {
                var iv = RandomAES128Key();
                return AES128.EncryptCBC(paddedInput, randomKey, iv);
            }
        }

        public static bool ECBDetectionOracle(byte[] input)
        {
            var inputLength = input.Length;
            Console.WriteLine(inputLength);
            if (inputLength < 64)
                throw new ArgumentException("input buffer must be 64 or more bytes");
            var second = new ArraySegment<byte>(input, 16, 16).ToArray();
            var third = new ArraySegment<byte>(input, 32, 16).ToArray();

            return second.SequenceEqual(third);
        }

        public static byte[] EncryptAES128ECBWithUnknownString(byte[] input, byte[] randomKey)
        {
            var unknown = Convert.FromBase64String("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");
            var payload = new byte[input.Length + unknown.Length];
            input.CopyTo(payload, 0);
            unknown.CopyTo(payload, input.Length);
            return AES128.EncryptECB(payload, randomKey);
        }

        public static int DiscoverBlockSizeOfAESECBCipher(byte[] randomKey)
        {
            var i = 1;
            byte[] lastBlock = new byte[1];
            lastBlock[0] = 0x00;

            while (true)
            {
                var input = Encoding.UTF8.GetBytes(new String('A', i+1));
                var output = EncryptAES128ECBWithUnknownString(input, randomKey);

                var inspectOutput = new ArraySegment<byte>(output, 0, i).ToArray();
                var inspectLastBlock = new ArraySegment<byte>(lastBlock, 0, i).ToArray();
                if (inspectOutput.SequenceEqual<byte>(inspectLastBlock))
                    return i;
                else
                {
                    i++;
                    lastBlock = output;
                }
            }
        }

        public static string ByteAtATimeECBDecryptionSimple()
        {
            var randomKey = Crypto.RandomAES128Key();
            var cipherBlockSize = Crypto.DiscoverBlockSizeOfAESECBCipher(randomKey);
            var cipherSearchBlockSize = cipherBlockSize * 20;
            var foundText = new StringBuilder();


            for (var i = cipherSearchBlockSize - 1; i > 0; i--)
            {
                var plainText = Encoding.UTF8.GetBytes(new string('A', i));
                var cipherText = Crypto.EncryptAES128ECBWithUnknownString(plainText, randomKey);
                if (cipherText.Length < cipherSearchBlockSize) break;
                var cipherTextTruncated = new ArraySegment<byte>(cipherText, 0, cipherSearchBlockSize).ToArray();
                var searchCiphers = new Dictionary<string, char>();
                for (char j = (char)0x00; j <= (char)0xFF; j++)
                {
                    var searchBlock = new byte[cipherSearchBlockSize];
                    plainText.CopyTo(searchBlock, 0);
                    Encoding.UTF8.GetBytes(foundText.ToString()).CopyTo(searchBlock, plainText.Length);
                    searchBlock[searchBlock.Length - 1] = (byte)j;
                    var searchBlockEnc = Crypto.EncryptAES128ECBWithUnknownString(searchBlock, randomKey);
                    searchCiphers[Encoding.UTF8.GetString(new ArraySegment<byte>(searchBlockEnc, 0, cipherSearchBlockSize).ToArray())] = j;
                }
                foundText.Append(searchCiphers[Encoding.UTF8.GetString(cipherTextTruncated)]);
            }

            return foundText.ToString();
        }
    }
}
