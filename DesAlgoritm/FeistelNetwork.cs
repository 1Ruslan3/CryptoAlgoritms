namespace DesAlgoritm
{
    public class FeistelNetwork
    {
        #region Fields
        private readonly IKeyExpansion _keyExpansion;
        private readonly IEncryptionRound _roundFunction;
        private readonly int _blockSizeBytes;
        private byte[][]? _subKeys;
        private bool _initialized;

        #endregion

        #region Constructor

        public FeistelNetwork(IKeyExpansion keyExpansion, IEncryptionRound roundFunction, int blockSizeBytes)
        {
            _keyExpansion = keyExpansion ?? throw new ArgumentNullException(nameof(keyExpansion));
            _roundFunction = roundFunction ?? throw new ArgumentNullException(nameof(roundFunction));
            if (blockSizeBytes <= 0) throw new ArgumentException("blockSizeBytes must be > 0");
            _blockSizeBytes = blockSizeBytes;
        }

        #endregion
       
        #region Methods
        public bool IsInitialized => _initialized;

        public void Initialize(byte[] key)
        {
            _subKeys = _keyExpansion.ExpandKey(key);
            _initialized = true;
        }

        public void Reset()
        {
            _subKeys = null;
            _initialized = false;
        }

        public byte[] Encrypt(byte[] inputBlock)
        {
            if (!_initialized) throw new InvalidOperationException("FeistelNetwork not initialized.");
            if (inputBlock.Length != _blockSizeBytes) throw new ArgumentException("Input block size mismatch.");

            int half = _blockSizeBytes / 2;
            byte[] L = new byte[half];
            byte[] R = new byte[half];
            Array.Copy(inputBlock, 0, L, 0, half);
            Array.Copy(inputBlock, half, R, 0, half);

            for (int r = 0; r < _subKeys!.Length; r++)
            {
                byte[] fOut = _roundFunction.EncryptRound(R, _subKeys[r]);
                byte[] newR = XorArrays(L, fOut);
                L = R;
                R = newR;
            }

            byte[] outBlock = new byte[_blockSizeBytes];
            Array.Copy(R, 0, outBlock, 0, half);
            Array.Copy(L, 0, outBlock, half, half);
            return outBlock;
        }

        public byte[] Decrypt(byte[] inputBlock)
        {
            if (!_initialized) throw new InvalidOperationException("FeistelNetwork not initialized.");
            if (inputBlock.Length != _blockSizeBytes) throw new ArgumentException("Input block size mismatch.");

            int half = _blockSizeBytes / 2;
            byte[] L = new byte[half];
            byte[] R = new byte[half];
            Array.Copy(inputBlock, 0, L, 0, half);
            Array.Copy(inputBlock, half, R, 0, half);

            for (int r = _subKeys!.Length - 1; r >= 0; r--)
            {
                byte[] fOut = _roundFunction.EncryptRound(R, _subKeys[r]);
                byte[] newR = XorArrays(L, fOut);
                L = R;
                R = newR;
            }

            byte[] outBlock = new byte[_blockSizeBytes];
            Array.Copy(R, 0, outBlock, 0, half);
            Array.Copy(L, 0, outBlock, half, half);
            return outBlock;
        }

        private static byte[] XorArrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) throw new ArgumentException("Lengths must match for XOR.");
            byte[] outBytes = new byte[a.Length];
            for (int i = 0; i < a.Length; i++)
                outBytes[i] = (byte)(a[i] ^ b[i]);
            return outBytes;
        }

        #endregion
    }
}