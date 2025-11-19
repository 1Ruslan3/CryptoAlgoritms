using ContextCipher;

namespace RijndaelAlgoritm
{
    public sealed class RijndaelCipher : ISymmetricBlockCipher  
    {
        private int Nb;   
        private int Nk;  
        private int Nr;  
        private byte[][] RoundKeys; 
        private readonly byte[] sBox = new byte[256];
        private readonly byte[] invSBox = new byte[256];
        private readonly int gfPoly;

        public int BlockSize => Nb * 4; 

        public bool IsInitialized => throw new NotImplementedException();

        public RijndaelCipher(int blockBits = 128, int gfPolynomial = 0x1B)
        {
            if (blockBits % 32 != 0) throw new ArgumentException("blockBits must be multiple of 32");
            Nb = blockBits / 32;
            gfPoly = gfPolynomial;
            RoundKeys = Array.Empty<byte[]>();
        }

        public void Initialize(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length % 4 != 0) throw new ArgumentException("Key length must be a multiple of 4 bytes (32-bit words).");

            Nk = key.Length / 4;
            Nr = Math.Max(Nb, Nk) + 6;

            GenerateSBoxes_FIPS197();
            RoundKeys = ExpandKey(key);
        }

        public byte[] Encrypt(byte[] block)
        {
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSize) throw new ArgumentException($"Block size must be {BlockSize} bytes.");
            return EncryptBlock(block);
        }

        public byte[] Decrypt(byte[] block)
        {
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BlockSize) throw new ArgumentException($"Block size must be {BlockSize} bytes.");
            return DecryptBlock(block);
        }

        private byte[][] ExpandKey(byte[] key)
        {
            int wordCount = Nb * (Nr + 1);
            byte[][] w = new byte[wordCount][];
            int i = 0;
            while (i < Nk)
            {
                w[i] = new byte[4];
                Buffer.BlockCopy(key, 4 * i, w[i], 0, 4);
                i++;
            }

            byte[] temp = new byte[4];
            i = Nk;
            while (i < wordCount)
            {
                Buffer.BlockCopy(w[i - 1], 0, temp, 0, 4);

                if (i % Nk == 0)
                {
                    RotWordInplace(temp);
                    SubWordInplace(temp);
                    temp[0] ^= Rcon(i / Nk);
                }
                else if (Nk > 6 && (i % Nk) == 4)
                {
                    SubWordInplace(temp);
                }

                w[i] = new byte[4];
                for (int t = 0; t < 4; t++)
                    w[i][t] = (byte)(w[i - Nk][t] ^ temp[t]);

                i++;
            }

            return w;
        }

        private byte[] EncryptBlock(byte[] inputBlock)
        {
            byte[,] state = new byte[4, Nb];
            for (int i = 0; i < inputBlock.Length; i++)
                state[i % 4, i / 4] = inputBlock[i];

            AddRoundKey(state, 0);

            for (int round = 1; round < Nr; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, round);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, Nr);

            byte[] output = new byte[BlockSize];
            for (int i = 0; i < output.Length; i++)
                output[i] = state[i % 4, i / 4];

            return output;
        }

        private byte[] DecryptBlock(byte[] inputBlock)
        {
            byte[,] state = new byte[4, Nb];
            for (int i = 0; i < inputBlock.Length; i++)
                state[i % 4, i / 4] = inputBlock[i];

            AddRoundKey(state, Nr);

            for (int round = Nr - 1; round >= 1; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, round);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, 0);

            byte[] output = new byte[BlockSize];
            for (int i = 0; i < output.Length; i++)
                output[i] = state[i % 4, i / 4];

            return output;
        }

        private void AddRoundKey(byte[,] state, int round)
        {
            for (int c = 0; c < Nb; c++)
                for (int r = 0; r < 4; r++)
                    state[r, c] ^= RoundKeys[round * Nb + c][r];
        }

        private void SubBytes(byte[,] s)
        {
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < Nb; c++)
                    s[r, c] = sBox[s[r, c]];
        }

        private void InvSubBytes(byte[,] s)
        {
            for (int r = 0; r < 4; r++)
                for (int c = 0; c < Nb; c++)
                    s[r, c] = invSBox[s[r, c]];
        }

        private void ShiftRows(byte[,] s)
        {
            for (int r = 1; r < 4; r++)
                RotateRowLeft(s, r, r);
        }

        private void InvShiftRows(byte[,] s)
        {
            for (int r = 1; r < 4; r++)
                RotateRowRight(s, r, r);
        }

        private void MixColumns(byte[,] s)
        {
            for (int c = 0; c < Nb; c++)
            {
                byte a0 = s[0, c], a1 = s[1, c], a2 = s[2, c], a3 = s[3, c];
                s[0, c] = (byte)(GFMul(2, a0) ^ GFMul(3, a1) ^ a2 ^ a3);
                s[1, c] = (byte)(a0 ^ GFMul(2, a1) ^ GFMul(3, a2) ^ a3);
                s[2, c] = (byte)(a0 ^ a1 ^ GFMul(2, a2) ^ GFMul(3, a3));
                s[3, c] = (byte)(GFMul(3, a0) ^ a1 ^ a2 ^ GFMul(2, a3));
            }
        }

        private void InvMixColumns(byte[,] s)
        {
            for (int c = 0; c < Nb; c++)
            {
                byte a0 = s[0, c], a1 = s[1, c], a2 = s[2, c], a3 = s[3, c];
                s[0, c] = (byte)(GFMul(0x0e, a0) ^ GFMul(0x0b, a1) ^ GFMul(0x0d, a2) ^ GFMul(0x09, a3));
                s[1, c] = (byte)(GFMul(0x09, a0) ^ GFMul(0x0e, a1) ^ GFMul(0x0b, a2) ^ GFMul(0x0d, a3));
                s[2, c] = (byte)(GFMul(0x0d, a0) ^ GFMul(0x09, a1) ^ GFMul(0x0e, a2) ^ GFMul(0x0b, a3));
                s[3, c] = (byte)(GFMul(0x0b, a0) ^ GFMul(0x0d, a1) ^ GFMul(0x09, a2) ^ GFMul(0x0e, a3));
            }
        }

        private void RotateRowLeft(byte[,] s, int row, int shift)
        {
            shift %= Nb;
            if (shift == 0) return;
            byte[] tmp = new byte[Nb];
            for (int c = 0; c < Nb; c++)
                tmp[c] = s[row, (c + shift) % Nb];
            for (int c = 0; c < Nb; c++)
                s[row, c] = tmp[c];
        }

        private void RotateRowRight(byte[,] s, int row, int shift)
        {
            shift %= Nb;
            if (shift == 0) return;
            byte[] tmp = new byte[Nb];
            for (int c = 0; c < Nb; c++)
                tmp[(c + shift) % Nb] = s[row, c];
            for (int c = 0; c < Nb; c++)
                s[row, c] = tmp[c];
        }

        private void RotWordInplace(byte[] w)
        {
            byte t = w[0];
            w[0] = w[1];
            w[1] = w[2];
            w[2] = w[3];
            w[3] = t;
        }

        private void SubWordInplace(byte[] w)
        {
            for (int i = 0; i < 4; i++) w[i] = sBox[w[i]];
        }

        private byte Rcon(int i)
        {
            byte c = 1;
            if (i == 0) return 0;
            while (i > 1)
            {
                byte b = (byte)((c << 1) ^ ((c & 0x80) != 0 ? 0x1B : 0x00));
                c = b;
                i--;
            }
            return c;
        }

        private int GFMul(int a, int b)
        {
            int res = 0;
            int aa = a & 0xFF;
            int bb = b & 0xFF;
            for (int i = 0; i < 8; i++)
            {
                if ((bb & 1) != 0) res ^= aa;
                bool hi = (aa & 0x80) != 0;
                aa = (aa << 1) & 0xFF;
                if (hi) aa ^= gfPoly;
                bb >>= 1;
            }
            return res & 0xFF;
        }

        private byte MultiplicativeInverseGF(byte a)
        {
            if (a == 0) return 0;
            byte result = 1, baseVal = a;
            int exp = 254; 
            while (exp > 0)
            {
                if ((exp & 1) != 0) result = (byte)GFMul(result, baseVal);
                baseVal = (byte)GFMul(baseVal, baseVal);
                exp >>= 1;
            }
            return result;
        }

        private static byte Rotl8(byte x, int shift)
        {
            shift &= 7;
            return (byte)(((x << shift) | (x >> (8 - shift))) & 0xFF);
        }

        private static byte AffineTransform_FIPS(byte b)
            => (byte)(b ^ Rotl8(b, 1) ^ Rotl8(b, 2) ^ Rotl8(b, 3) ^ Rotl8(b, 4) ^ 0x63);

        private static byte InverseAffineTransform_FIPS(byte s)
            => (byte)(Rotl8(s, 1) ^ Rotl8(s, 3) ^ Rotl8(s, 6) ^ 0x05);

        private void GenerateSBoxes_FIPS197()
        {
            for (int x = 0; x < 256; x++)
            {
                byte a = (byte)x;
                byte b = (a == 0) ? (byte)0 : MultiplicativeInverseGF(a);
                sBox[x] = AffineTransform_FIPS(b);
            }

            for (int y = 0; y < 256; y++)
            {
                byte s = (byte)y;
                byte b = InverseAffineTransform_FIPS(s);
                byte a = (b == 0) ? (byte)0 : MultiplicativeInverseGF(b);
                invSBox[y] = a;
            }
        }

        public void Reset()
        {
            RoundKeys = Array.Empty<byte[]>();
        }
    }
}
