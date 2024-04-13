using System;
using System.Security.Cryptography;
using System.Text;

class AES
{
    private byte[,] sBox = new byte[,]
    {
        {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
        {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
        {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
        {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
        {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
        {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
        {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
        {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
        {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
        {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
        {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
        {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
        {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
        {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
        {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
        {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}
    };

    private byte[,] invSBox = new byte[,]
    {
        {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
        {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
        {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
        {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
        {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
        {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
        {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
        {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
        {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
        {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
        {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
        {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
        {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
        {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
        {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D}
    };

    private byte[,] roundKeys;

    private byte[][] Rcon = {
        new byte[] {0x01, 0x00, 0x00, 0x00},
        new byte[] {0x02, 0x00, 0x00, 0x00},
        new byte[] {0x04, 0x00, 0x00, 0x00},
        new byte[] {0x08, 0x00, 0x00, 0x00},
        new byte[] {0x10, 0x00, 0x00, 0x00},
        new byte[] {0x20, 0x00, 0x00, 0x00},
        new byte[] {0x40, 0x00, 0x00, 0x00},
        new byte[] {0x80, 0x00, 0x00, 0x00},
        new byte[] {0x1B, 0x00, 0x00, 0x00},
        new byte[] {0x36, 0x00, 0x00, 0x00}
    };

    public AES(byte[] key)
    {
        roundKeys = KeyExpansion(key);
    }

    private byte[,] KeyExpansion(byte[] key)
    {
        int Nk = key.Length / 4;
        int Nb = 4;
        int Nr = Nk + 6;

        byte[,] w = new byte[4, Nb * (Nr + 1)];
        byte[] temp = new byte[4];

        for (int i = 0; i < Nk; i++)
        {
            w[0, i] = key[i * 4];
            w[1, i] = key[i * 4 + 1];
            w[2, i] = key[i * 4 + 2];
            w[3, i] = key[i * 4 + 3];
        }

        for (int i = Nk; i < Nb * (Nr + 1); i++)
        {
            for (int t = 0; t < 4; t++)
            {
                temp[t] = w[t, i - 1];
            }

            if (i % Nk == 0)
            {
                temp = SubWord(RotWord(temp));
                temp[0] ^= Rcon[i % Nk][0];
            }
            else if (Nk > 6 && i % Nk == 4)
            {
                temp = SubWord(temp);
            }

            for (int t = 0; t < 4; t++)
            {
                w[t, i] = (byte)(w[t, i - Nk] ^ temp[t]);
            }
        }

        return w;
    }

    private byte[] SubWord(byte[] word)
    {
        for (int i = 0; i < 4; i++)
        {
            word[i] = sBox[word[i] >> 4, word[i] & 0x0F];
        }
        return word;
    }

    private byte[] RotWord(byte[] word)
    {
        byte tmp = word[0];
        for (int i = 0; i < 3; i++)
        {
            word[i] = word[i + 1];
        }
        word[3] = tmp;
        return word;
    }

    private byte[,] AddRoundKey(byte[,] state, byte[,] roundKey, int round)
    {
        int Nb = 4;
        for (int c = 0; c < Nb; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                state[r, c] ^= roundKey[r, round * Nb + c];
            }
        }
        return state;
    }

    private byte[,] SubBytes(byte[,] state)
    {
        int Nb = 4;
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nb; c++)
            {
                state[r, c] = sBox[state[r, c] >> 4, state[r, c] & 0x0F];
            }
        }
        return state;
    }

    private byte[,] InvSubBytes(byte[,] state)
    {
        int Nb = 4;
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < Nb; c++)
            {
                state[r, c] = invSBox[state[r, c] >> 4, state[r, c] & 0x0F];
            }
        }
        return state;
    }

    private byte[,] ShiftRows(byte[,] state)
    {
        byte[,] newState = new byte[4, 4];
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < 4; c++)
            {
                newState[r, c] = state[r, (c + r) % 4];
            }
        }
        return newState;
    }

    private byte[,] InvShiftRows(byte[,] state)
    {
        byte[,] newState = new byte[4, 4];
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < 4; c++)
            {
                newState[r, c] = state[r, (c - r + 4) % 4];
            }
        }
        return newState;
    }

    public byte[,] MixColumns(byte[,] state)
    {
        byte[,] newState = new byte[4, 4];
        for (int c = 0; c < 4; c++)
        {
            newState[0, c] = (byte)(Multiply(0x02, state[0, c]) ^ Multiply(0x03, state[1, c]) ^ state[2, c] ^ state[3, c]);
            newState[1, c] = (byte)(state[0, c] ^ Multiply(0x02, state[1, c]) ^ Multiply(0x03, state[2, c]) ^ state[3, c]);
            newState[2, c] = (byte)(state[0, c] ^ state[1, c] ^ Multiply(0x02, state[2, c]) ^ Multiply(0x03, state[3, c]));
            newState[3, c] = (byte)(Multiply(0x03, state[0, c]) ^ state[1, c] ^ state[2, c] ^ Multiply(0x02, state[3, c]));
        }
        Console.WriteLine(newState);
        return newState;
    }

    public byte[,] InvMixColumns(byte[,] state)
    {
        byte[,] newState = new byte[4, 4];
        for (int c = 0; c < 4; c++)
        {
            newState[0, c] = (byte)(Multiply(0x0E, state[0, c]) ^ Multiply(0x0B, state[1, c]) ^ Multiply(0x0D, state[2, c]) ^ Multiply(0x09, state[3, c]));
            newState[1, c] = (byte)(Multiply(0x09, state[0, c]) ^ Multiply(0x0E, state[1, c]) ^ Multiply(0x0B, state[2, c]) ^ Multiply(0x0D, state[3, c]));
            newState[2, c] = (byte)(Multiply(0x0D, state[0, c]) ^ Multiply(0x09, state[1, c]) ^ Multiply(0x0E, state[2, c]) ^ Multiply(0x0B, state[3, c]));
            newState[3, c] = (byte)(Multiply(0x0B, state[0, c]) ^ Multiply(0x0D, state[1, c]) ^ Multiply(0x09, state[2, c]) ^ Multiply(0x0E, state[3, c]));
        }
        return newState;
    }

    private byte Multiply(int a, byte b)
    {
        int result = 0;
        while (a != 0)
        {
            if ((a & 1) != 0)
            {
                result ^= b;
            }
            bool hiBitSet = (b & 0x80) != 0;
            b <<= 1;
            if (hiBitSet)
            {
                b ^= 0x1B;
            }
            a >>= 1;
        }
        return (byte)result;
    }

    public byte[] EncryptBlock(byte[] input)
    {
        byte[,] state = new byte[4, 4];
        for (int i = 0; i < 16; i++)
        {
            state[i / 4, i % 4] = input[i];
        }

        int Nr = roundKeys.GetLength(1) / 4 - 1;
      
        state = AddRoundKey(state, roundKeys, 0);

        for (int round = 1; round < Nr; round++)
        {
            state = SubBytes(state);
            state = ShiftRows(state);
            state = MixColumns(state);
            state = AddRoundKey(state, roundKeys, round);
        }

        state = SubBytes(state);
        state = ShiftRows(state);
        state = AddRoundKey(state, roundKeys, Nr);

        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            output[i] = state[i / 4, i % 4];
        }

        return output;
    }

    private byte[] DecryptBlock(byte[] input)
    {
        byte[,] state = new byte[4, 4];
        for (int i = 0; i < 16; i++)
        {
            state[i / 4, i % 4] = input[i];
        }

        int Nr = roundKeys.GetLength(1) / 4 - 1;

        state = AddRoundKey(state, roundKeys, Nr);

        for (int round = Nr - 1; round > 0; round--)
        {
            state = InvShiftRows(state);
            state = InvSubBytes(state);
            state = AddRoundKey(state, roundKeys, round);
            state = InvMixColumns(state);
        }

        state = InvShiftRows(state);
        state = InvSubBytes(state);
        state = AddRoundKey(state, roundKeys, 0);

        byte[] output = new byte[16];
        for (int i = 0; i < 16; i++)
        {
            output[i] = state[i / 4, i % 4];
        }

        return output;
    }

    public byte[] Encrypt(byte[] input)
    {
        int blockSize = 16;
        int blockCount = (input.Length + blockSize - 1) / blockSize;
        byte[] encrypted = new byte[blockCount * blockSize];
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[blockSize];
            int length = Math.Min(input.Length - i * blockSize, blockSize);
            Array.Copy(input, i * blockSize, block, 0, length);
            Array.Clear(block, length, blockSize - length);

            byte[] encryptedBlock = EncryptBlock(block);
            Array.Copy(encryptedBlock, 0, encrypted, i * blockSize, blockSize);
        }
        return encrypted;
    }

    public byte[] Decrypt(byte[] input)
    {
        int blockSize = 16;
        int blockCount = input.Length / blockSize;
        byte[] decrypted = new byte[blockCount * blockSize];
        for (int i = 0; i < blockCount; i++)
        {
            byte[] block = new byte[blockSize];
            Array.Copy(input, i * blockSize, block, 0, blockSize);

            byte[] decryptedBlock = DecryptBlock(block);
            Array.Copy(decryptedBlock, 0, decrypted, i * blockSize, blockSize);
        }
        return decrypted;
    }

    public static void Main()
    {
        string original = "Hello, my name Ilya!!";
        string key = "SecretKey1234567";
        //string key = "00";

        AES aes = new AES(Encoding.UTF8.GetBytes(key));
        byte[] encrypted = aes.Encrypt(Encoding.UTF8.GetBytes(original));
        byte[] decrypted = aes.Decrypt(encrypted);
        
        Console.WriteLine("Оригинал:   {0}", original);
        Console.WriteLine("Зашифрованный:  {0}", Convert.ToBase64String(encrypted));
        Console.WriteLine("Дешифрованный:  {0}", Encoding.UTF8.GetString(decrypted).TrimEnd('\0'));
        Console.WriteLine($"ZZZZZZZZZZZZZZZZZ key: {BitConverter.ToString(Encoding.UTF8.GetBytes(key))}");

        
        Console.WriteLine("1", aes.MixColumns(new byte[4, 4]));


        byte[] encryptedData = Convert.FromBase64String("n+wxm2hVcrznFiOT9jV0Gw/lxS89ArQzShX/jZAHokM=");


        string expectedPlainText = "Hello, my name Ilya!";
        byte[] expectedData = System.Text.Encoding.UTF8.GetBytes(expectedPlainText);


        byte[] possibleKey = new byte[16];

        for (ulong i = 0; i < ulong.MaxValue; i++)
        {

            BitConverter.GetBytes(i).CopyTo(possibleKey, 0);
            //Console.WriteLine($"Trying key: {BitConverter.ToString(possibleKey)}");
            aes = new AES(possibleKey);


            byte[] decryptedData = aes.Decrypt(encryptedData);


            if (ByteArraysEqual(decryptedData, expectedData))
            {
                Console.WriteLine($"Key found: {BitConverter.ToString(possibleKey)}");
                break;
            }
        }

        Console.WriteLine("Key not found.");
    }


    static bool ByteArraysEqual(byte[] a1, byte[] a2)
    {
        if (a1 == null && a2 == null)
            return true;
        if (a1 == null || a2 == null || a1.Length != a2.Length)
            return false;
        for (int i = 0; i < a1.Length; ++i)
        {
            if (a1[i] != a2[i])
                return false;
        }
        return true;
    }
}
