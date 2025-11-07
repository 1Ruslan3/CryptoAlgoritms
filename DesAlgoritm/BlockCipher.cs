namespace DesAlgoritm
{
    public enum CipherMode
    {
        ECB,
        CBC
    }

    public enum PaddingMode
    {
        None,
        ZeroPadding,
        PKCS7
    }

    public class BlockCipher : IDisposable
    {
        private readonly ISymmetricBlockCipher _cipher;
        private readonly int _blockSize;
        private readonly CipherMode _mode;
        private readonly PaddingMode _padding;
        private byte[]? _iv;
        private bool _disposed;

        public BlockCipher(
            int blockSizeBytes,
            byte[] key,
            CipherMode mode,
            PaddingMode padding,
            byte[]? iv,
            ISymmetricBlockCipher algorithm)
        {
            if (blockSizeBytes <= 0)
                throw new ArgumentException("Block size must be positive.");
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            _blockSize = blockSizeBytes;
            _cipher = algorithm;
            _mode = mode;
            _padding = padding;

            if (mode == CipherMode.CBC)
            {
                if (iv == null || iv.Length != _blockSize)
                    throw new ArgumentException($"IV must be {_blockSize} bytes for CBC mode.");
                _iv = (byte[])iv.Clone();
            }

            _cipher.Initialize(key);
        }

        public byte[] Encrypt(byte[] plainData)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(BlockCipher));
            if (plainData == null) throw new ArgumentNullException(nameof(plainData));

            byte[] padded = ApplyPadding(plainData);
            List<byte> result = new List<byte>();
            byte[] prevBlock = _mode == CipherMode.CBC && _iv != null ? (byte[])_iv.Clone() : new byte[_blockSize];

            for (int i = 0; i < padded.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(padded, i, block, 0, _blockSize);

                if (_mode == CipherMode.CBC)
                    XorBlocks(block, prevBlock);

                byte[] encrypted = _cipher.Encrypt(block);

                if (_mode == CipherMode.CBC)
                    Array.Copy(encrypted, prevBlock, _blockSize);

                result.AddRange(encrypted);
            }

            return result.ToArray();
        }

        public byte[] Decrypt(byte[] cipherData)
        {
            if (_disposed) throw new ObjectDisposedException(nameof(BlockCipher));
            if (cipherData == null) throw new ArgumentNullException(nameof(cipherData));
            if (cipherData.Length % _blockSize != 0)
                throw new ArgumentException("Ciphertext length must be multiple of block size.");

            List<byte> result = new List<byte>();
            byte[] prevBlock = _mode == CipherMode.CBC && _iv != null ? (byte[])_iv.Clone() : new byte[_blockSize];

            for (int i = 0; i < cipherData.Length; i += _blockSize)
            {
                byte[] block = new byte[_blockSize];
                Array.Copy(cipherData, i, block, 0, _blockSize);

                byte[] decrypted = _cipher.Decrypt(block);

                if (_mode == CipherMode.CBC)
                    XorBlocks(decrypted, prevBlock);

                result.AddRange(decrypted);

                if (_mode == CipherMode.CBC)
                    Array.Copy(block, prevBlock, _blockSize);
            }

            return RemovePadding(result.ToArray());
        }

        private void XorBlocks(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++)
                a[i] ^= b[i];
        }

        private byte[] ApplyPadding(byte[] data)
        {
            int paddingSize = _blockSize - (data.Length % _blockSize);
            if (paddingSize == 0 && _padding != PaddingMode.None)
                paddingSize = _blockSize;

            byte[] result;

            switch (_padding)
            {
                case PaddingMode.None:
                    if (data.Length % _blockSize != 0)
                        throw new ArgumentException("Data length must be multiple of block size when using Padding.None.");
                    result = data;
                    break;

                case PaddingMode.ZeroPadding:
                    result = new byte[data.Length + paddingSize];
                    Array.Copy(data, result, data.Length);
                    break;

                case PaddingMode.PKCS7:
                    result = new byte[data.Length + paddingSize];
                    Array.Copy(data, result, data.Length);
                    for (int i = data.Length; i < result.Length; i++)
                        result[i] = (byte)paddingSize;
                    break;

                default:
                    throw new NotSupportedException($"Unsupported padding: {_padding}");
            }

            return result;
        }

        private byte[] RemovePadding(byte[] data)
        {
            if (_padding == PaddingMode.None)
                return data;

            if (_padding == PaddingMode.ZeroPadding)
            {
                int trim = data.Length;
                while (trim > 0 && data[trim - 1] == 0)
                    trim--;
                byte[] unpadded = new byte[trim];
                Array.Copy(data, unpadded, trim);
                return unpadded;
            }

            if (_padding == PaddingMode.PKCS7)
            {
                if (data.Length == 0)
                    throw new ArgumentException("Invalid PKCS7 padding.");

                int padValue = data[data.Length - 1];
                if (padValue <= 0 || padValue > _blockSize)
                    throw new ArgumentException("Invalid PKCS7 padding value.");

                for (int i = data.Length - padValue; i < data.Length; i++)
                    if (data[i] != padValue)
                        throw new ArgumentException("Corrupted PKCS7 padding.");

                byte[] unpadded = new byte[data.Length - padValue];
                Array.Copy(data, 0, unpadded, 0, unpadded.Length);
                return unpadded;
            }

            throw new NotSupportedException($"Unsupported padding: {_padding}");
        }

        public void Dispose()
        {
            _cipher.Reset();
            _disposed = true;
        }
    }
}