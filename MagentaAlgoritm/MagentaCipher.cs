using ContextCipher;

namespace MagentaAlgoritm
{
    public sealed class MagentaCipher : ISymmetricBlockCipher
    {
        private const int BLOCK_BYTES = 16;
        private const int HALF_BYTES = 8;
        private FeistelNetwork _feistel;
        private bool _initialized;
        public int BlockSize => BLOCK_BYTES;
        public bool IsInitialized => _initialized;

        public MagentaCipher()
        {
            _feistel = new FeistelNetwork(new MagentaKeyExpansion(6), new MagentaRoundFunction(), BLOCK_BYTES);
            _initialized = false;
        }

        public sealed class MagentaKeyExpansion : IKeyExpansion
        {
             private readonly int _rounds;

            public MagentaKeyExpansion(int rounds, byte[]? key = null)
            {
                if (rounds <= 0) throw new ArgumentOutOfRangeException(nameof(rounds));
                _rounds = rounds;
            }

            public byte[][] ExpandKey(byte[] key)
            {
                if (key == null) throw new ArgumentNullException(nameof(key));
                if (!(key.Length == 16 || key.Length == 24 || key.Length == 32))
                    throw new ArgumentException("MAGENTA: key must be 16,24 or 32 bytes.");

                int kcount = key.Length / 8; 
                byte[][] K = new byte[kcount][];
                for (int i = 0; i < kcount; i++)
                {
                    K[i] = new byte[8];
                    Buffer.BlockCopy(key, i * 8, K[i], 0, 8);
                }


                // 16 bytes (K1,K2) -> K1,K1,K2,K2,K1,K1  (6 rounds)
                // 24 bytes (K1,K2,K3) -> K1,K2,K3,K3,K2,K1 (6 rounds)
                // 32 bytes (K1,K2,K3,K4) -> K1,K2,K3,K4,K4,K3,K2,K1 (8 rounds)
                byte[][] subKeys = new byte[_rounds][];
                if (kcount == 2)
                {
                    if (_rounds != 6) throw new ArgumentException("MAGENTA: expected 6 rounds for 16/24-byte keys");
                    subKeys[0] = (byte[])K[0].Clone();
                    subKeys[1] = (byte[])K[0].Clone();
                    subKeys[2] = (byte[])K[1].Clone();
                    subKeys[3] = (byte[])K[1].Clone();
                    subKeys[4] = (byte[])K[0].Clone();
                    subKeys[5] = (byte[])K[0].Clone();
                }
                else if (kcount == 3)
                {
                    if (_rounds != 6) throw new ArgumentException("MAGENTA: expected 6 rounds for 16/24-byte keys");
                    subKeys[0] = (byte[])K[0].Clone();
                    subKeys[1] = (byte[])K[1].Clone();
                    subKeys[2] = (byte[])K[2].Clone();
                    subKeys[3] = (byte[])K[2].Clone();
                    subKeys[4] = (byte[])K[1].Clone();
                    subKeys[5] = (byte[])K[0].Clone();
                }
                else 
                {
                    if (_rounds != 8) throw new ArgumentException("MAGENTA: expected 8 rounds for 32-byte keys");
                    subKeys[0] = (byte[])K[0].Clone();
                    subKeys[1] = (byte[])K[1].Clone();
                    subKeys[2] = (byte[])K[2].Clone();
                    subKeys[3] = (byte[])K[3].Clone();
                    subKeys[4] = (byte[])K[3].Clone();
                    subKeys[5] = (byte[])K[2].Clone();
                    subKeys[6] = (byte[])K[1].Clone();
                    subKeys[7] = (byte[])K[0].Clone();
                }

                return subKeys;
            }
        }

        public sealed class MagentaRoundFunction : IEncryptionRound
        {   
            private const int BLOCK = 16;
            private const int HALF = 8;

            private const int GF_POLY = 0x165;
            private readonly byte[] ftable = new byte[256]; 
            private readonly byte[] exp = new byte[255 + 1];
            public MagentaRoundFunction()
            {
                BuildFieldAndF();
            }

            private void BuildFieldAndF()
            {
                exp[0] = 1;
                for (int i = 1; i <= 254; i++)
                {
                    exp[i] = GfMul(exp[i - 1], 0x02);
                }

                for (int x = 0; x <= 254; x++)
                    ftable[x] = exp[x];
                ftable[255] = 0;
            }

            public byte[] EncryptRound(byte[] rightHalf, byte[] roundKey)
            {
                if (rightHalf == null) throw new ArgumentNullException(nameof(rightHalf));
                if (roundKey == null) throw new ArgumentNullException(nameof(roundKey));
                if (rightHalf.Length != HALF) throw new ArgumentException("rightHalf must be 8 bytes.");
                if (roundKey.Length != HALF) throw new ArgumentException("roundKey must be 8 bytes.");

                byte[] state = new byte[BLOCK];

                Buffer.BlockCopy(rightHalf, 0, state, 0, HALF);
                Buffer.BlockCopy(roundKey, 0, state, HALF, HALF);

                state = T(state);
                state = T(state);
                state = T(state);

                byte[] outBytes = new byte[HALF];
                for (int i = 0; i < HALF; i++)
                    outBytes[i] = state[i * 2];

                return outBytes;
            }

            private byte[] PI(byte[] inState)
            {
                if (inState.Length != BLOCK) throw new ArgumentException("PI expects 16-byte input");
                byte[] outS = new byte[BLOCK];
                for (int i = 0; i < 8; i++)
                {
                    byte xi = inState[i];
                    byte yi = inState[i + 8];

                    byte fy = ftable[yi];
                    byte fx = ftable[xi];

                    byte a = ftable[(byte)(xi ^ fy)];
                    byte b = ftable[(byte)(yi ^ fx)];

                    outS[2 * i] = a;
                    outS[2 * i + 1] = b;
                }
                return outS;
            }

            private byte[] T(byte[] s)
            {
                byte[] t = s;

                t = PI(t);
                t = PI(t);
                t = PI(t);
                t = PI(t);
                return t;
            }

            private static byte GfMul(int aInt, int bInt)
            {
                int a = aInt & 0xFF;
                int b = bInt & 0xFF;
                int res = 0;
                for (int i = 0; i < 8; i++)
                {
                    if ((b & 1) != 0) res ^= a;
                    b >>= 1;
                    bool hi = (a & 0x80) != 0;
                    a = (a << 1) & 0x1FF; 
                    if (hi)
                    {
                        a ^= GF_POLY;
                    }
                    a &= 0xFF;
                }
                return (byte)(res & 0xFF);
            }
        }

        public void Initialize(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (!(key.Length == 16 || key.Length == 24 || key.Length == 32))
                throw new ArgumentException("MAGENTA: key must be 16, 24 or 32 bytes.", nameof(key));

            int rounds = (key.Length == 32) ? 8 : 6;

            _feistel = new FeistelNetwork(new MagentaKeyExpansion(rounds, key), new MagentaRoundFunction(), BLOCK_BYTES);

            _feistel.Initialize(key); 
            _initialized = true;
        }

        public byte[] Encrypt(byte[] block)
        {
            if (!_initialized) throw new InvalidOperationException("MagentaCipher not initialized.");
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BLOCK_BYTES) throw new ArgumentException($"Block must be {BLOCK_BYTES} bytes.");

            return _feistel.Encrypt(block);
        }

        public byte[] Decrypt(byte[] block)
        {
            if (!_initialized) throw new InvalidOperationException("MagentaCipher not initialized.");
            if (block == null) throw new ArgumentNullException(nameof(block));
            if (block.Length != BLOCK_BYTES) throw new ArgumentException($"Block must be {BLOCK_BYTES} bytes.");

            return _feistel.Decrypt(block);
        }

        public void Reset()
        {
            _feistel.Reset();
            _initialized = false;
        }
    }
    
}
