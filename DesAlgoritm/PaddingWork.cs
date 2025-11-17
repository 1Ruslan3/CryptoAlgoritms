namespace DesAlgoritm
{
    public sealed class PaddingWork : IPadding
    {
        private readonly PaddingMode _mode;
        private readonly Random _rnd;
        private Dictionary<PaddingMode, Func<byte[], int, byte[]>> _paddingActions;

        public PaddingWork(PaddingMode mode)
        {
            _mode = mode;
            _rnd = new Random();
            
            _paddingActions = new Dictionary<PaddingMode, Func<byte[], int, byte[]>>();

            InitPaddingActions(); 
        }

        public byte[] ApplyPadding(byte[] data, int blockSize)
        {
            return _paddingActions[_mode](data, blockSize);
        }

        public byte[] RemovePadding(byte[] data, int blockSize)
        {
             if (_mode == PaddingMode.ZeroPadding)
                return data;

            int padLen = data[^1];
            if (padLen <= 0 || padLen > blockSize)
                return data;

            byte[] result = new byte[data.Length - padLen];
            Buffer.BlockCopy(data, 0, result, 0, result.Length);
            return result;
        }

        private void InitPaddingActions()
        {
            _paddingActions = new Dictionary<PaddingMode, Func<byte[], int, byte[]>>()
            {
                { PaddingMode.ZeroPadding, ApplyZeroPadding },
                { PaddingMode.PKCS7, ApplyPKCS7Padding },
                { PaddingMode.ANSI_X923, ApplyANSIX923Padding },
                { PaddingMode.ISO_10126, ApplyISO10126Padding }
            };
        }

        private byte[] ApplyZeroPadding(byte[] data, int blockSize)
        {
            int padLen = blockSize - (data.Length % blockSize);
            if (padLen == blockSize) padLen = 0;

            if (padLen == 0) return data;

            byte[] padded = new byte[data.Length + padLen];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);

            return padded;
        }

        private byte[] ApplyPKCS7Padding(byte[] data, int blockSize)
        {
            int padLen = blockSize - (data.Length % blockSize);
            if (padLen == 0) padLen = blockSize;

            byte[] padded = new byte[data.Length + padLen];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);

            for (int i = data.Length; i < padded.Length; i++)
                padded[i] = (byte)padLen;

            return padded;
        }

        private byte[] ApplyANSIX923Padding(byte[] data, int blockSize)
        {
            int padLen = blockSize - (data.Length % blockSize);
            if (padLen == 0) padLen = blockSize;

            byte[] padded = new byte[data.Length + padLen];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);

            for (int i = data.Length; i < padded.Length - 1; i++)
                padded[i] = 0x00;

            padded[^1] = (byte)padLen;
            return padded;
        }

        private byte[] ApplyISO10126Padding(byte[] data, int blockSize)
        {
            int padLen = blockSize - (data.Length % blockSize);
            if (padLen == 0) padLen = blockSize;

            byte[] padded = new byte[data.Length + padLen];
            Buffer.BlockCopy(data, 0, padded, 0, data.Length);

            for (int i = data.Length; i < padded.Length - 1; i++)
                padded[i] = (byte)_rnd.Next(0, 256);

            padded[^1] = (byte)padLen;
            return padded;
        }
    }
}