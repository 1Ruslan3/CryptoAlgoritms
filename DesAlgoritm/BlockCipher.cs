namespace DesAlgoritm
{
    public class BlockCipher
    {
        #region Fields
        private readonly ISymmetricBlockCipher _cipher;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        private readonly byte[] _iv;
        private readonly int _blockSize;
        private readonly ICipherMode _cipherMode;

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
            _padding = padding;
            _iv = iv ?? new byte[_blockSize];
            _cipher = algorithm;
            _cipher.Initialize(key);
            _cipherMode = new ModeWork(_blockSize, _iv);
        }

        #endregion

        #region Encrypt/Decrypt
        public byte[] Encrypt(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] padded = ApplyPadding(data);
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

            return RemovePadding(output);
        }

        #endregion

        #region Helper's methods
        private byte[] ApplyPadding(byte[] data)
        {
            if (_padding == PaddingMode.None)
            {
                if (data.Length % _blockSize != 0)
                    throw new ArgumentException("Data length not multiple of block size in None mode.");
                return data;
            }

            int padLen = _blockSize - (data.Length % _blockSize);
            if (padLen == 0)
                padLen = _blockSize;

            byte[] padded = new byte[data.Length + padLen];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);

            switch (_padding)
            {
                case PaddingMode.ZeroPadding:
                    break;

                case PaddingMode.PKCS7:
                    for (int i = data.Length; i < padded.Length; i++)
                        padded[i] = (byte)padLen;
                    break;

                case PaddingMode.ANSI_X923:
                    for (int i = data.Length; i < padded.Length - 1; i++)
                        padded[i] = 0x00;
                    padded[padded.Length - 1] = (byte)padLen;
                    break;

                case PaddingMode.ISO_10126:
                    Random rnd = new Random();
                    for (int i = data.Length; i < padded.Length - 1; i++)
                        padded[i] = (byte)rnd.Next(0, 256);
                    padded[padded.Length - 1] = (byte)padLen;
                    break;
            }

            return padded;
        }

        private byte[] RemovePadding(byte[] data)
        {
            if (_padding == PaddingMode.None || _padding == PaddingMode.ZeroPadding)
                return data;

            byte padLen = data[data.Length - 1];
            if (padLen <= 0 || padLen > _blockSize)
                return data;

            byte[] result = new byte[data.Length - padLen];
            Buffer.BlockCopy(data, 0, result, 0, result.Length);
            return result;
        }

        private static void Xor(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++)
                a[i] ^= b[i];
        }

        private static void IncrementCounter(byte[] counter)
        {
            for (int i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                    break;
            }
        }


        #endregion
    }
}
