using ContextCipher;

namespace DesAlgoritm
{   
    public class DealCipher : ISymmetricBlockCipher
    {
        #region Fields
        private readonly FeistelNetwork _feistel;
        private bool _initialized;
        #endregion

        #region Constructo
        public DealCipher()
        {
            _feistel = new FeistelNetwork(new DealKeyExpansion(), new DealRoundFunction(), 16);
            _initialized = false;
        }
        #endregion

        #region Properties
        public int BlockSize => 16;
        public bool IsInitialized => _initialized;
        #endregion

        #region Nexted class
        public class DealKeyExpansion : IKeyExpansion
        {
            public byte[][] ExpandKey(byte[] key)
            {
                if (key == null) throw new ArgumentNullException(nameof(key));

                int keyLen = key.Length;
                int rounds;
                if (keyLen == 16 || keyLen == 24) rounds = 6;
                else if (keyLen == 32) rounds = 8;
                else throw new ArgumentException("DEAL Key length must be 16, 24 or 32 bytes.");

                const int DES_KEY_BYTES = 8;
                byte[][] subKeys = new byte[rounds][];

                int required = rounds * DES_KEY_BYTES;
                byte[] buffer = new byte[required];
                int pos = 0;
                while (pos < required)
                {
                    int toCopy = Math.Min(key.Length, required - pos);
                    Buffer.BlockCopy(key, 0, buffer, pos, toCopy);
                    pos += toCopy;
                }

                for (int i = 0; i < rounds; i++)
                {
                    int off = i * DES_KEY_BYTES;
                    int rot = i % DES_KEY_BYTES;
                    if (rot != 0)
                    {
                        byte[] tmp = new byte[DES_KEY_BYTES];
                        for (int j = 0; j < DES_KEY_BYTES; j++)
                            tmp[j] = buffer[off + ((j + rot) % DES_KEY_BYTES)];
                        Buffer.BlockCopy(tmp, 0, buffer, off, DES_KEY_BYTES);
                    }

                    int nextOff = ((i + 1) * DES_KEY_BYTES) % required;
                    for (int j = 0; j < DES_KEY_BYTES; j++)
                        buffer[off + j] ^= buffer[nextOff + j];
                }

                for (int i = 0; i < rounds; i++)
                {
                    subKeys[i] = new byte[DES_KEY_BYTES];
                    Buffer.BlockCopy(buffer, i * DES_KEY_BYTES, subKeys[i], 0, DES_KEY_BYTES);
                }

                return subKeys;
            }
        }

        public class DealRoundFunction : IEncryptionRound
        {
            public byte[] EncryptRound(byte[] rightHalf, byte[] roundKey)
            {
                if (rightHalf == null) throw new ArgumentNullException(nameof(rightHalf));
                if (roundKey == null) throw new ArgumentNullException(nameof(roundKey));
                if (rightHalf.Length != 8) throw new ArgumentException("rightHalf must be 8 bytes.");
                if (roundKey.Length != 8) throw new ArgumentException("roundKey must be 8 bytes.");

                var des = new DesCipher();
                des.Initialize(roundKey);

                return des.Encrypt(rightHalf);
            }
        }
        #endregion

        #region Methods
        public void Initialize(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (!(key.Length == 16 || key.Length == 24 || key.Length == 32))
                throw new ArgumentException("DEAL key length must be 16, 24 or 32 bytes.");

            _feistel.Initialize(key);
            _initialized = true;
        }

        public byte[] Encrypt(byte[] inputBlock)
        {
            if (!_initialized) throw new InvalidOperationException("DealCipher not initialized.");
            if (inputBlock == null) throw new ArgumentNullException(nameof(inputBlock));
            if (inputBlock.Length != BlockSize) throw new ArgumentException($"Block must be {BlockSize} bytes.");

            return _feistel.Encrypt(inputBlock); 
        }

        public byte[] Decrypt(byte[] inputBlock)
        {
            if (!_initialized) throw new InvalidOperationException("DealCipher not initialized.");
            if (inputBlock == null) throw new ArgumentNullException(nameof(inputBlock));
            if (inputBlock.Length != BlockSize) throw new ArgumentException($"Block must be {BlockSize} bytes.");

            return _feistel.Decrypt(inputBlock);
        }

        public void Reset()
        {
            _feistel.Reset();
            _initialized = false;
        }
        #endregion
    }
}
