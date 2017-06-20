using System;
using System.Collections.Generic;
using System.Linq;

namespace com.defrobo.cryptopals
{
    public static class AES128
    {
        public static byte[] sbox = new byte[256]
        {
                0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
                0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
                0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
                0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
                0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
                0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
                0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
                0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
                0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
                0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
                0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
                0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
                0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
                0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
                0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
                0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
                0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
                0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
                0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
                0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
                0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
                0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
                0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
                0x54, 0xbb, 0x16
        };

        public static byte[] sboxInv = new byte[256]
        {
                0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
                0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
                0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb ,0x54,
                0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
                0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
                0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8,
                0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
                0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab,
                0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
                0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
                0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b ,0x3a, 0x91, 0x11, 0x41,
                0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
                0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
                0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d,
                0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
                0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
                0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
                0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60,
                0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
                0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
                0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b,
                0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
                0x21, 0x0c, 0x7d
        };

        public static byte[] rcon = new byte[256]
        {
                0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
                0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
                0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
                0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66,
                0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
                0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
                0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
                0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61,
                0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
                0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
                0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc,
                0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
                0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
                0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
                0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
                0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
                0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4,
                0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
                0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08,
                0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
                0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
                0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2,
                0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74,
                0xe8, 0xcb, 0x8d
        };

        public static byte[] KeySchedule(byte[] key)
        {
            var output = new Queue<byte>(key);
            var i = 1;
            while (output.Count < 176)
            {
                var t = new byte[4];
                Array.Copy(output.ToArray(), output.Count - 4, t, 0, 4);
                if (output.Count % 16 == 0)
                {
                    t = KeyScheduleCore(t, i++);
                }
                for (var a = 0; a < 4; a++)
                {
                    output.Enqueue((byte)(output.ToArray()[output.Count - 16] ^ t[a]));
                }
            }
            return output.ToArray();
        }

        private static byte[] KeyScheduleCore(byte[] key, int iteration)
        {
            var output = new byte[4];
            Array.Copy(key, output, 4);
            output.ShiftLeft(1);
            output[0] = sbox[output[0]];
            output[1] = sbox[output[1]];
            output[2] = sbox[output[2]];
            output[3] = sbox[output[3]];
            output[0] = (byte)(output[0] ^ rcon[iteration]);
            return output;
        }

        public static byte[] DecryptCBC(byte[] input, byte[] key, byte[] iv)
        {
            var output = new List<byte>();
            var expandedKey = KeySchedule(key);
            var lastBlock = new byte[iv.Length];
            Array.Copy(iv, lastBlock, iv.Length);
            for (var i = 0; i < input.Length / 16; i++)
            {
                var block = new ArraySegment<byte>(input, i * 16, 16).ToArray();
                var cipherBlock = new byte[block.Length];
                Array.Copy(block, cipherBlock, block.Length);
                var decryptedBlock = DecryptBlock(block, expandedKey);
                output.AddRange(Crypto.FixedXOR(decryptedBlock, lastBlock));
                lastBlock = cipherBlock;
            }
            return output.ToArray();
        }

        public static byte[] EncryptCBC(byte[] input, byte[] key, byte[] iv)
        {
            var output = new List<byte>();
            var expandedKey = KeySchedule(key);
            var lastBlock = new byte[iv.Length];
            Array.Copy(iv, lastBlock, iv.Length);
            for (var i = 0; i < input.Length / 16; i++)
            {
                var block = new ArraySegment<byte>(input, i * 16, 16).ToArray();
                var xoredBlock = Crypto.FixedXOR(block, lastBlock);
                var encryptedBlock = EncryptBlock(xoredBlock, expandedKey);
                output.AddRange(encryptedBlock);
                lastBlock = encryptedBlock;
            }
            return output.ToArray();
        }

        public static byte[] DecryptECB(byte[] input, byte[] key)
        {
            var expandedKey = KeySchedule(key);
            var output = new List<byte>();
            for (var i = 0; i < input.Length / 16; i++)
            {
                var block = new ArraySegment<byte>(input, i * 16, 16).ToArray();
                output.AddRange(DecryptBlock(block, expandedKey));
            }
            return output.ToArray();
        }

        public static byte[] EncryptECB(byte[] input, byte[] key)
        {
            var expandedKey = KeySchedule(key);
            var output = new List<byte>();
            for (var i = 0; i < input.Length / 16; i++)
            {
                var block = new ArraySegment<byte>(input, i * 16, 16).ToArray();
                output.AddRange(EncryptBlock(block, expandedKey));
            }
            return output.ToArray();
        }

        public static byte[] DecryptBlock(byte[] input, byte[] expandedKey)
        {
            var state = StateFromInput(input);
            var roundKey = CreateRoundKey(expandedKey, 10);
            AddRoundKey(state, roundKey);
            for (var i = 9; i > 0; i--)
            {
                roundKey = CreateRoundKey(expandedKey, i);
                InvAESRound(state, roundKey);
            }
            InvShiftRows(state);
            InvSubBytes(state);
            roundKey = CreateRoundKey(expandedKey, 0);
            AddRoundKey(state, roundKey);

            return OutputFromState(state);
        }

        public static byte[] EncryptBlock(byte[] input, byte[] expandedKey)
        {
            var state = StateFromInput(input);
            var roundKey = CreateRoundKey(expandedKey, 0);
            AddRoundKey(state, roundKey);
            for (var i = 1; i < 10; i++)
            {
                roundKey = CreateRoundKey(expandedKey, i);
                AESRound(state, roundKey);
            }
            ShiftRows(state);
            SubBytes(state);
            roundKey = CreateRoundKey(expandedKey, 10);
            AddRoundKey(state, roundKey);

            return OutputFromState(state);
        }

        private static byte[][] StateFromInput(byte[] input)
        {
            var output = new byte[4][];
            for (var row = 0; row < 4; row++)
            {
                output[row] = new byte[4];
                for (var col = 0; col < 4; col++)
                {
                    output[row][col] = input[row + 4 * col];
                }
            }
            return output;
        }

        private static byte[] OutputFromState(byte[][] state)
        {
            var output = new byte[16];
            for (var row = 0; row < 4; row++)
            {
                for (var col = 0; col < 4; col++)
                {
                    output[row + 4 * col] = state[row][col];

                }
            }
            return output;
        }

        private static void AddRoundKey(byte[][] state, byte[] roundKey)
        {
            for (var col = 0; col < 4; col++)
            {
                for (var row = 0; row < 4; row++)
                {
                    state[row][col] = (byte)(state[row][col] ^ roundKey[row + 4 * col]);
                }
            }
        }

        private static byte[] CreateRoundKey(byte[] expandedKey, int round)
        {
            return new ArraySegment<byte>(expandedKey, round * 16, 16).ToArray();
        }

        private static void AESRound(byte[][] state, byte[] roundKey)
        {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, roundKey);
        }

        private static void InvAESRound(byte[][] state, byte[] roundKey)
        {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, roundKey);
            InvMixColumns(state);
        }

        private static void ShiftRows(byte[][] state)
        {
            state[1].ShiftLeft(1);
            state[2].ShiftLeft(2);
            state[3].ShiftLeft(3);
        }

        private static void InvShiftRows(byte[][] state)
        {
            state[1].ShiftRight(1);
            state[2].ShiftRight(2);
            state[3].ShiftRight(3);
        }

        private static void SubBytes(byte[][] state)
        {
            for (var row = 0; row < 4; row++)
            {
                for (var col = 0; col < 4; col++)
                {
                    state[row][col] = sbox[state[row][col]];

                }
            }
        }
        private static void InvSubBytes(byte[][] state)
        {
            for (var row = 0; row < 4; row++)
            {
                for (var col = 0; col < 4; col++)
                {
                    state[row][col] = sboxInv[state[row][col]];

                }
            }
        }

        private static void MixColumns(byte[][] state)
        {
            for (var col = 0; col < 4; col++)
            {
                var column = new byte[4];
                for (var row = 0; row < 4; row++)
                {
                    column[row] = state[row][col];
                }
                GmixColumn(column);
                for (var row = 0; row < 4; row++)
                {
                    state[row][col] = column[row];
                }
            }
        }

        private static void InvMixColumns(byte[][] state)
        {
            for (var col = 0; col < 4; col++)
            {
                var column = new byte[4];
                for (var row = 0; row < 4; row++)
                {
                    column[row] = state[row][col];
                }
                InvGmixColumn(column);
                for (var row = 0; row < 4; row++)
                {
                    state[row][col] = column[row];
                }
            }
        }

        private static void GmixColumn(byte[] column)
        {
            var a = new byte[4];
            Array.Copy(column, a, 4);
            column[0] = (byte)(Gmul(a[0], 2) ^ Gmul(a[3], 1) ^ Gmul(a[2], 1) ^ Gmul(a[1], 3));
            column[1] = (byte)(Gmul(a[1], 2) ^ Gmul(a[0], 1) ^ Gmul(a[3], 1) ^ Gmul(a[2], 3));
            column[2] = (byte)(Gmul(a[2], 2) ^ Gmul(a[1], 1) ^ Gmul(a[0], 1) ^ Gmul(a[3], 3));
            column[3] = (byte)(Gmul(a[3], 2) ^ Gmul(a[2], 1) ^ Gmul(a[1], 1) ^ Gmul(a[0], 3));
        }

        private static void InvGmixColumn(byte[] column)
        {
            var a = new byte[4];
            Array.Copy(column, a, 4);
            column[0] = (byte)(Gmul(a[0], 14) ^ Gmul(a[3], 9) ^ Gmul(a[2], 13) ^ Gmul(a[1], 11));
            column[1] = (byte)(Gmul(a[1], 14) ^ Gmul(a[0], 9) ^ Gmul(a[3], 13) ^ Gmul(a[2], 11));
            column[2] = (byte)(Gmul(a[2], 14) ^ Gmul(a[1], 9) ^ Gmul(a[0], 13) ^ Gmul(a[3], 11));
            column[3] = (byte)(Gmul(a[3], 14) ^ Gmul(a[2], 9) ^ Gmul(a[1], 13) ^ Gmul(a[0], 11));
        }

        private static byte Gmul(byte a, int bAsInt)
        {
            var p = default(byte);
            var b = (byte)bAsInt;
            var hiBitSet = 0x00;
            for (var i = 0; i < 8; i++)
            {
                if ((b & 1) == 1)
                {
                    p ^= a;
                }
                hiBitSet = (a & 0x80);
                a <<= 1;
                if (hiBitSet == 0x80)
                {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            return p;
        }
    }
}
