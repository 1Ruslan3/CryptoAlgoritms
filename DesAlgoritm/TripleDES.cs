using ContextCipher;

namespace DesAlgoritm
{
    public enum TripleDesMode
    {
        EDE, 
        EEE  
    }

    public sealed class TripleDesCipher : ISymmetricBlockCipher
    {
        private readonly DesCipher _d1 = new DesCipher();
        private readonly DesCipher _d2 = new DesCipher();
        private readonly DesCipher _d3 = new DesCipher();

        private bool _initialized = false;
        private readonly TripleDesMode _mode;

        public int BlockSize => 8;

        public TripleDesCipher(TripleDesMode mode = TripleDesMode.EDE)
        {
            _mode = mode;
        }
        public void Initialize(byte[] key)
        {
            if (key == null) throw new ArgumentNullException(nameof(key));
            if (key.Length != 16 && key.Length != 24)
                throw new ArgumentException("TripleDES key must be 16 or 24 bytes.");

            byte[] k1 = new byte[8];
            byte[] k2 = new byte[8];
            byte[] k3 = new byte[8];

            Array.Copy(key, 0, k1, 0, 8);
            Array.Copy(key, 8, k2, 0, 8);

            if (key.Length == 16)
            {
                Array.Copy(k1, 0, k3, 0, 8);
            }
            else
            {
                Array.Copy(key, 16, k3, 0, 8);
            }

            _d1.Reset();
            _d2.Reset();
            _d3.Reset();

            _d1.Initialize(k1);
            _d2.Initialize(k2);
            _d3.Initialize(k3);

            _initialized = _d1.IsInitialized && _d2.IsInitialized && _d3.IsInitialized;
            if (!_initialized)
                throw new InvalidOperationException("Failed to initialize TripleDES sub-ciphers.");
        }

        public byte[] Encrypt(byte[] inputBlock)
        {
            if (inputBlock == null || inputBlock.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes.");
            if (!_initialized)
                throw new InvalidOperationException("TripleDES not initialized.");

            if (_mode == TripleDesMode.EDE)
            {
                var t1 = _d1.Encrypt(inputBlock);
                var t2 = _d2.Decrypt(t1);
                var c = _d3.Encrypt(t2);
                return c;
            }
            else 
            {
                var t1 = _d1.Encrypt(inputBlock);
                var t2 = _d2.Encrypt(t1);
                var c = _d3.Encrypt(t2);
                return c;
            }
        }

        public byte[] Decrypt(byte[] inputBlock)
        {
            if (inputBlock == null || inputBlock.Length != BlockSize)
                throw new ArgumentException($"Block must be {BlockSize} bytes.");
            if (!_initialized)
                throw new InvalidOperationException("TripleDES not initialized.");

            if (_mode == TripleDesMode.EDE)
            {
                var t1 = _d3.Decrypt(inputBlock);
                var t2 = _d2.Encrypt(t1);
                var p = _d1.Decrypt(t2);
                return p;
            }
            else 
            {
                var t1 = _d3.Decrypt(inputBlock);
                var t2 = _d2.Decrypt(t1);
                var p = _d1.Decrypt(t2);
                return p;
            }
        }

        public void Reset()
        {
            _d1.Reset();
            _d2.Reset();
            _d3.Reset();
            _initialized = false;
        }

        public bool IsInitialized => _initialized;
    }
}
