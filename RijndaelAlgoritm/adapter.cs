using ContextCipher;

namespace RijndaelAlgoritm
{
    public sealed class RijndaelAdapter : ISymmetricBlockCipher  
    {
        private readonly RijndaelCipher _cipher;

        public int BlockSize => _cipher.BlockSize;

        public bool IsInitialized => throw new NotImplementedException();

        private bool _initialized = false;

        public RijndaelAdapter(int blockBits = 128)
        {
            _cipher = new RijndaelCipher(blockBits);
        }

        public void Initialize(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));
                
            if (key.Length % 4 != 0)
                throw new ArgumentException("Key length must be a multiple of 4 bytes.", nameof(key));

            _cipher.Initialize(key);
            _initialized = true;
        }

        public byte[] Encrypt(byte[] block)
        {
            if (!_initialized)
                throw new InvalidOperationException("Cipher is not initialized.");

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be exactly {BlockSize} bytes.");

            return _cipher.Encrypt(block);
        }

        public byte[] Decrypt(byte[] block)
        {
            if (!_initialized)
                throw new InvalidOperationException("Cipher is not initialized.");

            if (block == null)
                throw new ArgumentNullException(nameof(block));

            if (block.Length != BlockSize)
                throw new ArgumentException($"Block must be exactly {BlockSize} bytes.");

            return _cipher.Decrypt(block);
        }

        public void Reset()
        {
            throw new NotImplementedException();
        }

    }
}
