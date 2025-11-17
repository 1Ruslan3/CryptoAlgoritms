// namespace DesAlgoritm
// {
//     public class ModeWork : ICipherMode
//     {
//         private int _blockSize;
//         private CipherMode _mode;
//         private byte[] _prev;
//         private byte[] _counter;
//         private Dictionary<CipherMode, Action<byte[], byte[], Func<byte[], byte[]>>> EncryptActions;
//         private Dictionary<CipherMode, Action<byte[], byte[], Func<byte[], byte[]>, Func<byte[], byte[]>>> DecryptActions;

//         public ModeWork(int blockSize, byte[] iv)
//         {
//             _blockSize = blockSize;
//             _prev = (byte[])iv.Clone();
//             _counter = (byte[])iv.Clone();

//             InitEncryptActions(); 
//             InitDecryptActions();
//         }

//         public void EncryptBlock(
//             CipherMode mode,
//             byte[] input,
//             byte[] output,
//             Func<byte[], byte[]> encryptBlock)
//         {
//             EncryptActions[_mode](input, output, encryptBlock);
//         }

//         public void DecryptBlock(
//             CipherMode mode,
//             byte[] input,
//             byte[] output,
//             Func<byte[], byte[]> encryptBlock,
//             Func<byte[], byte[]> decryptBlock)
//         {
//             DecryptActions[_mode](input, output, encryptBlock, decryptBlock);
//         }

//         public void Reset()
//         {
//             Array.Clear(_prev, 0, _prev.Length);
//             Array.Clear(_counter, 0, _counter.Length);
//         }


//         private void InitEncryptActions()
//         {
//             EncryptActions = new()
//             {
//                 {CipherMode.ECB, EncryptECB},
//                 {CipherMode.CBC, EncryptCBC},
//                 {CipherMode.PCBC, EncryptPCBC},
//                 {CipherMode.CFB, EncryptCFB},
//                 {CipherMode.OFB, EncryptOFB},
//                 {CipherMode.CTR, EncryptCTR},
//             };
//         }

//          private void InitDecryptActions()
//         {
//             throw new Exception("sd");
//         }

//         private void EncryptECB(byte[] block, byte[] output, Func<byte[], byte[]> enc)
//         {
//             output = enc(block);
//         }

//         private void EncryptCBC(byte[] block, byte[] output, Func<byte[], byte[]> enc)
//         {
//             Xor(block, _prev);
//             output = enc(block);
//             Buffer.BlockCopy(output, 0, _prev, 0, _blockSize);
//         }

//         private void EncryptPCBC(byte[] block, byte[] output, Func<byte[], byte[]> enc)
//         {
//             Xor(block, _prev);
//             output = enc(block);
//             byte[] temp = new byte[_blockSize];
//             Buffer.BlockCopy(block, 0, temp, 0, _blockSize);
//             Xor(temp, output);
//             Buffer.BlockCopy(temp, 0, _prev, 0, _blockSize);
//         }

//         private void EncryptCFB(byte[] block, byte[] output, Func<byte[], byte[]> enc)
//         {
//             byte[] feedback = enc(_prev);
//             Xor(block, feedback);
//             output = block;
//             Buffer.BlockCopy(output, 0, _prev, 0, _blockSize);
//         }

//         private void EncryptOFB(byte[] block, byte[] output, Func<byte[], byte[]> enc)
//         {
//             byte[] feedback = enc(_prev);
//             Buffer.BlockCopy(feedback, 0, _prev, 0, _blockSize);
//             output = new byte[_blockSize];
//             Buffer.BlockCopy(block, 0, output, 0, _blockSize);
//             Xor(output, feedback);
//         }

//         private void EncryptCTR(byte[] block, byte[] output, Func<byte[], byte[]> enc)
//         {
//             byte[] ctr = enc(_counter);
//             IncrementCounter(_counter);
//             output = new byte[_blockSize];
//             Buffer.BlockCopy(block, 0, output, 0, _blockSize);
//             Xor(output, ctr);
//         }

//         private static void Xor(byte[] a, byte[] b)
//         {
//             for (int i = 0; i < a.Length; i++)
//                 a[i] ^= b[i];
//         }

//         private static void IncrementCounter(byte[] counter)
//         {
//             for (int i = counter.Length - 1; i >= 0; i--)
//             {
//                 if (++counter[i] != 0)
//                     break;
//             }
//         }
//     }
// }

namespace DesAlgoritm
{
    public class ModeWork : ICipherMode
    {
        private readonly int _blockSize;
        private readonly byte[] _initialIV;

        private byte[] _prev;
        private byte[] _counter;

        private Dictionary<CipherMode, Action<byte[], byte[], Func<byte[], byte[]>>> EncryptActions;
        private Dictionary<CipherMode, Action<byte[], byte[], Func<byte[], byte[]>, Func<byte[], byte[]>>> DecryptActions;

        public ModeWork(int blockSize, byte[] iv)
        {
            _blockSize = blockSize;
            _initialIV = (byte[])iv.Clone();

            _prev = (byte[])iv.Clone();
            _counter = (byte[])iv.Clone();

            EncryptActions = new Dictionary<CipherMode, Action<byte[], byte[], Func<byte[], byte[]>>>();
            DecryptActions = new Dictionary<CipherMode, Action<byte[], byte[], Func<byte[], byte[]>, Func<byte[], byte[]>>>();

            InitEncryptActions();
            InitDecryptActions();
        }

        public void Reset()
        {
            Buffer.BlockCopy(_initialIV, 0, _prev, 0, _blockSize);
            Buffer.BlockCopy(_initialIV, 0, _counter, 0, _blockSize);
        }

        public void EncryptBlock(
            CipherMode mode,
            byte[] input,
            byte[] output,
            Func<byte[], byte[]> encBlock)
        {
            EncryptActions[mode](input, output, encBlock);
        }

        public void DecryptBlock(
            CipherMode mode,
            byte[] input,
            byte[] output,
            Func<byte[], byte[]> encBlock,
            Func<byte[], byte[]> decBlock)
        {
            DecryptActions[mode](input, output, encBlock, decBlock);
        }

        // =========================
        //  ENCRYPTION
        // =========================

        private void InitEncryptActions()
        {
            EncryptActions = new()
            {
                { CipherMode.ECB, EncryptECB },
                { CipherMode.CBC, EncryptCBC },
                { CipherMode.PCBC, EncryptPCBC },
                { CipherMode.CFB, EncryptCFB },
                { CipherMode.OFB, EncryptOFB },
                { CipherMode.CTR, EncryptCTR }
            };
        }

        private void EncryptECB(byte[] block, byte[] output, Func<byte[], byte[]> enc)
        {
            byte[] tmp = enc(block);
            Buffer.BlockCopy(tmp, 0, output, 0, _blockSize);
        }

        private void EncryptCBC(byte[] block, byte[] output, Func<byte[], byte[]> enc)
        {
            Xor(block, _prev);
            byte[] tmp = enc(block);

            Buffer.BlockCopy(tmp, 0, output, 0, _blockSize);
            Buffer.BlockCopy(tmp, 0, _prev, 0, _blockSize);
        }

        private void EncryptPCBC(byte[] block, byte[] output, Func<byte[], byte[]> enc)
        {
            var x = new byte[_blockSize];
            Buffer.BlockCopy(block, 0, x, 0, _blockSize);

            Xor(x, _prev);
            var cipher = enc(x);

            Buffer.BlockCopy(cipher, 0, output, 0, _blockSize);

            var prevXor = new byte[_blockSize];
            Buffer.BlockCopy(block, 0, prevXor, 0, _blockSize);
            Xor(prevXor, cipher);

            Buffer.BlockCopy(prevXor, 0, _prev, 0, _blockSize);
        }


        private void EncryptCFB(byte[] block, byte[] output, Func<byte[], byte[]> enc)
        {
            byte[] feedback = enc(_prev);

            byte[] cipher = new byte[_blockSize];
            Buffer.BlockCopy(block, 0, cipher, 0, _blockSize);
            Xor(cipher, feedback);

            Buffer.BlockCopy(cipher, 0, output, 0, _blockSize);
            Buffer.BlockCopy(cipher, 0, _prev, 0, _blockSize);
        }

        private void EncryptOFB(byte[] block, byte[] output, Func<byte[], byte[]> enc)
        {
            _prev = enc(_prev);

            byte[] buf = new byte[_blockSize];
            Buffer.BlockCopy(block, 0, buf, 0, _blockSize);
            Xor(buf, _prev);

            Buffer.BlockCopy(buf, 0, output, 0, _blockSize);
        }

        private void EncryptCTR(byte[] block, byte[] output, Func<byte[], byte[]> enc)
        {
            byte[] ctr = enc(_counter);
            IncrementCounter(_counter);

            byte[] buf = new byte[_blockSize];
            Buffer.BlockCopy(block, 0, buf, 0, _blockSize);
            Xor(buf, ctr);

            Buffer.BlockCopy(buf, 0, output, 0, _blockSize);
        }

        // =========================
        //  DECRYPTION
        // =========================

        private void InitDecryptActions()
        {
            DecryptActions = new()
            {
                { CipherMode.ECB, DecryptECB },
                { CipherMode.CBC, DecryptCBC },
                { CipherMode.PCBC, DecryptPCBC },
                { CipherMode.CFB, DecryptCFB },
                { CipherMode.OFB, DecryptOFB },
                { CipherMode.CTR, DecryptCTR }
            };
        }

        private void DecryptECB(byte[] block, byte[] output, Func<byte[], byte[]> enc, Func<byte[], byte[]> dec)
        {
            byte[] tmp = dec(block);
            Buffer.BlockCopy(tmp, 0, output, 0, _blockSize);
        }

        private void DecryptCBC(byte[] block, byte[] output, Func<byte[], byte[]> enc, Func<byte[], byte[]> dec)
        {
            byte[] plain = dec(block);
            Xor(plain, _prev);

            Buffer.BlockCopy(plain, 0, output, 0, _blockSize);
            Buffer.BlockCopy(block, 0, _prev, 0, _blockSize);
        }

      private void DecryptPCBC(byte[] input, byte[] output, Func<byte[], byte[]> enc, Func<byte[], byte[]> dec)
        {
            var decrypted = dec(input);

            var plaintext = new byte[_blockSize];
            Buffer.BlockCopy(decrypted, 0, plaintext, 0, _blockSize);
            Xor(plaintext, _prev);

            Buffer.BlockCopy(plaintext, 0, output, 0, _blockSize);

            var prevXor = new byte[_blockSize];
            Buffer.BlockCopy(plaintext, 0, prevXor, 0, _blockSize);
            Xor(prevXor, input);

            Buffer.BlockCopy(prevXor, 0, _prev, 0, _blockSize);
        }


        private void DecryptCFB(byte[] block, byte[] output, Func<byte[], byte[]> enc, Func<byte[], byte[]> dec)
        {
            byte[] feedback = enc(_prev);

            byte[] plain = new byte[_blockSize];
            Buffer.BlockCopy(block, 0, plain, 0, _blockSize);
            Xor(plain, feedback);

            Buffer.BlockCopy(plain, 0, output, 0, _blockSize);
            Buffer.BlockCopy(block, 0, _prev, 0, _blockSize);
        }

        private void DecryptOFB(byte[] block, byte[] output, Func<byte[], byte[]> enc, Func<byte[], byte[]> dec)
        {
            _prev = enc(_prev);

            byte[] plain = new byte[_blockSize];
            Buffer.BlockCopy(block, 0, plain, 0, _blockSize);
            Xor(plain, _prev);

            Buffer.BlockCopy(plain, 0, output, 0, _blockSize);
        }

        private void DecryptCTR(byte[] block, byte[] output, Func<byte[], byte[]> enc, Func<byte[], byte[]> dec)
        {
            byte[] ctr = enc(_counter);
            IncrementCounter(_counter);

            byte[] plain = new byte[_blockSize];
            Buffer.BlockCopy(block, 0, plain, 0, _blockSize);
            Xor(plain, ctr);

            Buffer.BlockCopy(plain, 0, output, 0, _blockSize);
        }

        // =========================
        //  HELPERS
        // =========================

        private static void Xor(byte[] a, byte[] b)
        {
            for (int i = 0; i < a.Length; i++)
                a[i] ^= b[i];
        }

        private static void IncrementCounter(byte[] c)
        {
            for (int i = c.Length - 1; i >= 0; i--)
                if (++c[i] != 0)
                    break;
        }
    }
}
