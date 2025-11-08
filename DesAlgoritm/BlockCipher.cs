namespace DesAlgoritm
{
    public class BlockCipher
    {
        #region Fields
        private readonly ISymmetricBlockCipher _cipher;
        private readonly int _blockSize;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        #endregion
      
        #region Constructor
        public BlockCipher(
            int blockSize,
            byte[] key,
            CipherMode mode,
            PaddingMode padding,
            byte[] iv,
            ISymmetricBlockCipher algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (key == null)
                throw new ArgumentNullException(nameof(key));
            if (blockSize <= 0)
                throw new ArgumentException("Block size must be positive.", nameof(blockSize));

            _blockSize = blockSize;
            _mode = mode;
            _padding = padding;
            _key = key;
            _iv = iv ?? new byte[_blockSize];
            _cipher = algorithm;
            _cipher.Initialize(_key);
        }

        #endregion

        #region Encrypt/Decrypt
        public byte[] Encrypt(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            byte[] padded = ApplyPadding(data);
            byte[] output = new byte[padded.Length];

            byte[] prevBlock = new byte[_blockSize];
            Buffer.BlockCopy(_iv, 0, prevBlock, 0, _blockSize);

            byte[] counter = new byte[_blockSize];
            Buffer.BlockCopy(_iv, 0, counter, 0, _blockSize);

            for (int offset = 0; offset < padded.Length; offset += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Buffer.BlockCopy(padded, offset, block, 0, _blockSize);
                byte[] encryptedBlock;

                switch (_mode)
                {
                    case CipherMode.ECB:
                        encryptedBlock = _cipher.Encrypt(block);
                        break;

                    case CipherMode.CBC:
                        Xor(block, prevBlock);
                        encryptedBlock = _cipher.Encrypt(block);
                        Buffer.BlockCopy(encryptedBlock, 0, prevBlock, 0, _blockSize);
                        break;

                    case CipherMode.PCBC:
                        Xor(block, prevBlock);
                        encryptedBlock = _cipher.Encrypt(block);
                        byte[] temp = new byte[_blockSize];
                        Buffer.BlockCopy(block, 0, temp, 0, _blockSize);
                        Xor(temp, encryptedBlock);
                        Buffer.BlockCopy(temp, 0, prevBlock, 0, _blockSize);
                        break;

                    case CipherMode.CFB:
                        byte[] feedback = _cipher.Encrypt(prevBlock);
                        Xor(block, feedback);
                        encryptedBlock = block;
                        Buffer.BlockCopy(encryptedBlock, 0, prevBlock, 0, _blockSize);
                        break;

                    case CipherMode.OFB:
                        byte[] ofbFeedback = _cipher.Encrypt(prevBlock);
                        Buffer.BlockCopy(ofbFeedback, 0, prevBlock, 0, _blockSize);
                        encryptedBlock = new byte[_blockSize];
                        Buffer.BlockCopy(block, 0, encryptedBlock, 0, _blockSize);
                        Xor(encryptedBlock, ofbFeedback);
                        break;

                    case CipherMode.CTR:
                        byte[] ctrEnc = _cipher.Encrypt(counter);
                        IncrementCounter(counter);
                        encryptedBlock = new byte[_blockSize];
                        Buffer.BlockCopy(block, 0, encryptedBlock, 0, _blockSize);
                        Xor(encryptedBlock, ctrEnc);
                        break;

                    default:
                        throw new NotSupportedException($"Mode {_mode} not supported.");
                }

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

            byte[] prevBlock = new byte[_blockSize];
            Buffer.BlockCopy(_iv, 0, prevBlock, 0, _blockSize);

            byte[] counter = new byte[_blockSize];
            Buffer.BlockCopy(_iv, 0, counter, 0, _blockSize);

            for (int offset = 0; offset < data.Length; offset += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Buffer.BlockCopy(data, offset, block, 0, _blockSize);
                byte[] decryptedBlock;

                switch (_mode)
                {
                    case CipherMode.ECB:
                        decryptedBlock = _cipher.Decrypt(block);
                        break;

                    case CipherMode.CBC:
                        decryptedBlock = _cipher.Decrypt(block);
                        Xor(decryptedBlock, prevBlock);
                        Buffer.BlockCopy(block, 0, prevBlock, 0, _blockSize);
                        break;

                    case CipherMode.PCBC:
                        decryptedBlock = _cipher.Decrypt(block);
                        byte[] temp = new byte[_blockSize];
                        Buffer.BlockCopy(decryptedBlock, 0, temp, 0, _blockSize);
                        Xor(decryptedBlock, prevBlock);
                        Xor(temp, block);
                        Buffer.BlockCopy(temp, 0, prevBlock, 0, _blockSize);
                        break;

                    case CipherMode.CFB:
                        byte[] feedback = _cipher.Encrypt(prevBlock);
                        decryptedBlock = new byte[_blockSize];
                        Buffer.BlockCopy(block, 0, decryptedBlock, 0, _blockSize);
                        Xor(decryptedBlock, feedback);
                        Buffer.BlockCopy(block, 0, prevBlock, 0, _blockSize);
                        break;

                    case CipherMode.OFB:
                        byte[] ofbFeedback = _cipher.Encrypt(prevBlock);
                        Buffer.BlockCopy(ofbFeedback, 0, prevBlock, 0, _blockSize);
                        decryptedBlock = new byte[_blockSize];
                        Buffer.BlockCopy(block, 0, decryptedBlock, 0, _blockSize);
                        Xor(decryptedBlock, ofbFeedback);
                        break;

                    case CipherMode.CTR:
                        byte[] ctrEnc = _cipher.Encrypt(counter);
                        IncrementCounter(counter);
                        decryptedBlock = new byte[_blockSize];
                        Buffer.BlockCopy(block, 0, decryptedBlock, 0, _blockSize);
                        Xor(decryptedBlock, ctrEnc);
                        break;

                    default:
                        throw new NotSupportedException($"Mode {_mode} not supported.");
                }

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
        // public void Dispose()
        // {
        //     if (!_disposed)
        //     {
        //         _cipher.Dispose();
        //         _disposed = true;
        //     }
        // }
    }
}
