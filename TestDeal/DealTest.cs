using System;
using System.Linq;
using Xunit;
using ContextCipher;
using DesAlgoritm;

namespace TestDeal
{
    public sealed class DealCipherTests
    {
        private static readonly byte[][] Keys =
        {
            Enumerable.Range(0, 16).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 24).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()
        };

        private static readonly byte[] IV =
        {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F
        };

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
            Enumerable.Range(1, 15).Select(i => (byte)i).ToArray(),
            Enumerable.Range(1, 16).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 31).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 64).Select(i => (byte)i).ToArray()
        };

        [Theory]
        [MemberData(nameof(GetTestCases))]
        public void EncryptDecrypt(
            byte[] key,
            CipherMode mode,
            PaddingMode padding,
            byte[] plainText)
        {
            var deal = new DealCipher();

            var cipher = new ContextCipher.ContextCipher(
                key: key,
                mode: mode,
                padding: padding,
                algorithm: deal,
                iv: IV);

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

        public static TheoryData<byte[], CipherMode, PaddingMode, byte[]> GetTestCases()
        {
            var data = new TheoryData<byte[], CipherMode, PaddingMode, byte[]>();

            foreach (var key in Keys)
            foreach (var mode in Modes)
            foreach (var padding in Paddings)
            foreach (var vector in TestData)
            {
                data.Add(key, mode, padding, vector);
            }

            return data;
        }
    }
}
