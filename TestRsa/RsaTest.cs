using System;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using Xunit;
using RsaAlgoritm;

namespace TestRsa
{
    public sealed class RsaCipherTests
    {
        private readonly IPrimalityTest _test =
            new MillerRabinTest(probability: 0.999, fermatRounds: 5);

        private const int BitLength = 1024;

        private static int GetSafeBlockSize(BigInteger n)
        {
            int bits = (int)Math.Floor(BigInteger.Log(n, 2));
            int halfBits = bits / 2;
            halfBits -= halfBits % 8;
            return halfBits / 8;
        }

        [Fact]
        public void EncryptDecrypt()
        {
            var rsa = new RsaCipher(_test, BitLength);
            var (n, _, _) = rsa.GetKeys();

            int blockSize = GetSafeBlockSize(n);

            byte[] original = new byte[blockSize];
            RandomNumberGenerator.Fill(original);

            BigInteger m = new BigInteger(original, true, true);
            BigInteger c = rsa.Encrypt(m);
            BigInteger d = rsa.Decrypt(c);

            byte[] recovered = d.ToByteArray(true, true);

            Assert.Equal(original, recovered);
        }

        [Theory]
        [InlineData(1)]
        [InlineData(7)]
        [InlineData(64)]
        [InlineData(128)]
        [InlineData(511)]
        [InlineData(1024)]
        public void EncryptDecryptMultiBlock(int length)
        {
            var rsa = new RsaCipher(_test, BitLength);
            var (n, _, _) = rsa.GetKeys();

            int blockSize = GetSafeBlockSize(n);

            byte[] original = new byte[length];
            RandomNumberGenerator.Fill(original);

            using var ms = new MemoryStream();

            for (int i = 0; i < original.Length; i += blockSize)
            {
                int len = Math.Min(blockSize, original.Length - i);
                byte[] block = new byte[len];
                Array.Copy(original, i, block, 0, len);

                BigInteger m = new BigInteger(block, true, true);
                BigInteger c = rsa.Encrypt(m);
                BigInteger d = rsa.Decrypt(c);

                byte[] recovered = d.ToByteArray(true, true);

                if (recovered.Length > len)
                    ms.Write(recovered, recovered.Length - len, len);
                else if (recovered.Length < len)
                {
                    byte[] fixedBlock = new byte[len];
                    Array.Copy(recovered, 0, fixedBlock, len - recovered.Length, recovered.Length);
                    ms.Write(fixedBlock);
                }
                else
                    ms.Write(recovered);
            }

            Assert.Equal(original, ms.ToArray());
        }

        [Theory]
        [InlineData(1)]
        [InlineData(32)]
        [InlineData(128)]
        [InlineData(512)]
        [InlineData(1024)]
        [InlineData(4096)]
        public void FileProcessor(int length)
        {
            var rsa = new RsaCipher(_test, BitLength);
            var processor = new RsaCipher.FileProcessor(rsa);

            byte[] data = new byte[length];
            RandomNumberGenerator.Fill(data);

            string input = Path.GetTempFileName();
            string enc = Path.GetTempFileName();
            string dec = Path.GetTempFileName();

            try
            {
                File.WriteAllBytes(input, data);

                processor.EncryptFile(input, enc);
                processor.DecryptFile(enc, dec);

                byte[] result = File.ReadAllBytes(dec);

                Assert.Equal(data, result);
            }
            finally
            {
                File.Delete(input);
                File.Delete(enc);
                File.Delete(dec);
            }
        }

        [Fact]
        public void Keys()
        {
            var rsa = new RsaCipher(_test, BitLength);
            var (n, e, d) = rsa.GetKeys();

            BigInteger m = 123456;
            BigInteger c = BigInteger.ModPow(m, e, n);
            BigInteger recovered = BigInteger.ModPow(c, d, n);

            Assert.Equal(m, recovered);
        }
    }
}
