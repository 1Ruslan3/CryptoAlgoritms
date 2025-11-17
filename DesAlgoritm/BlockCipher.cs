namespace DesAlgoritm
{
    public class BlockCipher
    {
        #region Fields
        private readonly ISymmetricBlockCipher _cipher;
        private readonly ICipherMode _cipherMode;
        private readonly PaddingWork _padding;
        private readonly CipherMode _mode;
        private readonly int _blockSize;
        private readonly byte[] _iv;
        #endregion
      
        #region Constructor
        public BlockCipher(
            byte[] key,
            CipherMode mode,
            PaddingMode padding,
            ISymmetricBlockCipher algorithm,
            byte[]? iv = null)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
                
            _blockSize = algorithm.BlockSize;
            if (_blockSize <= 0)
                throw new ArgumentException("Block size must be positive.", nameof(_blockSize));

            _mode = mode;
            _cipher = algorithm;
            _cipher.Initialize(key);
            _iv = iv ?? new byte[_blockSize];
            _padding = new PaddingWork(padding);
            _cipherMode = new ModeWork(_blockSize, _iv);
        }

        #endregion

        #region Encrypt/Decrypt
        public byte[] Encrypt(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] padded = _padding.ApplyPadding(data, _blockSize);
            byte[] output = new byte[padded.Length];

            _cipherMode.Reset();

            for (int offset = 0; offset < padded.Length; offset += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Buffer.BlockCopy(padded, offset, block, 0, _blockSize);

                byte[] encryptedBlock = new byte[_blockSize];
                
                _cipherMode.EncryptBlock(_mode, block, encryptedBlock, _cipher.Encrypt);

                Buffer.BlockCopy(encryptedBlock, 0, output, offset, _blockSize);
            }

            return output;
        }

        public byte[] Decrypt(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (data.Length % _blockSize != 0)
                throw new ArgumentException("Invalid data length (not a multiple of block size).");

            byte[] output = new byte[data.Length];

             _cipherMode.Reset();

            for (int offset = 0; offset < data.Length; offset += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Buffer.BlockCopy(data, offset, block, 0, _blockSize);

                byte[] decryptedBlock = new byte[_blockSize];
                _cipherMode.DecryptBlock(_mode, block, decryptedBlock, _cipher.Encrypt, _cipher.Decrypt);

                Buffer.BlockCopy(decryptedBlock, 0, output, offset, _blockSize);
            }

            return _padding.RemovePadding(output, _blockSize);
        }

        #endregion
    }
}
