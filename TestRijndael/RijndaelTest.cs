using System;
using System.Linq;
using Xunit;
using ContextCipher;
using RijndaelAlgoritm;

namespace TestRijndael
{
    public sealed class RijndaelCipherFullTests
    {
        private static readonly byte[][] Keys =
        {
            Enumerable.Range(0, 16).Select(i => (byte)i).ToArray(), 
            Enumerable.Range(0, 24).Select(i => (byte)i).ToArray(), 
            Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()  
        };
        private static readonly byte[] IV =
            Enumerable.Range(0, 16).Select(i => (byte)(i + 0x10)).ToArray();

        private static readonly CipherMode[] Modes =
        {
            CipherMode.ECB,
            CipherMode.CBC,
            CipherMode.PCBC,
            CipherMode.CFB,
            CipherMode.OFB,
            CipherMode.CTR
        };

        private static readonly PaddingMode[] Paddings =
        {
            PaddingMode.PKCS7,
            PaddingMode.ZeroPadding,
            PaddingMode.ANSI_X923,
            PaddingMode.ISO_10126
        };

        private static readonly byte[][] TestData =
        {
            Array.Empty<byte>(),
            new byte[] { 0x01 },
            new byte[] { 1,2,3,4,5,6,7 },
            new byte[] { 1,2,3,4,5,6,7,8 },
            Enumerable.Range(0, 15).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 64).Select(i => (byte)i).ToArray()
        };

        [Theory]
        [MemberData(nameof(GetTestCases))]
        public void Rijndael_Encrypt_Decrypt_ReturnsExpected(
            byte[] key,
            byte[] iv,
            CipherMode mode,
            PaddingMode padding,
            byte[] plainText)
        {
            var rijndael = new RijndaelCipher();

            var cipher = new ContextCipher.ContextCipher(
                key: key,
                mode: mode,
                padding: padding,
                algorithm: rijndael,
                iv: iv
            );

            byte[] encrypted = cipher.Encrypt(plainText);
            byte[] decrypted = cipher.Decrypt(encrypted);

            if (padding == PaddingMode.ZeroPadding)
            {
                Assert.True(decrypted.Length >= plainText.Length);

                for (int i = 0; i < plainText.Length; i++)
                    Assert.Equal(plainText[i], decrypted[i]);
            }
            else
            {
                Assert.Equal(plainText, decrypted);
            }
        }

        public static TheoryData<byte[], byte[], CipherMode, PaddingMode, byte[]> GetTestCases()
        {
            var data = new TheoryData<byte[], byte[], CipherMode, PaddingMode, byte[]>();

            foreach (var key in Keys)
            foreach (var mode in Modes)
            foreach (var padding in Paddings)
            foreach (var vector in TestData)
                data.Add(key, IV, mode, padding, vector);

            return data;
        }
    }
}
