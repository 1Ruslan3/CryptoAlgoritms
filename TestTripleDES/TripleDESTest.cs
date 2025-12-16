using System;
using System.Linq;
using Xunit;
using ContextCipher;
using DesAlgoritm;

namespace TestTripleDES
{
    public sealed class TripleDesCipherTests
    {
        private static readonly byte[][] Keys =
        {
            // 2-key TripleDES (K1,K2,K1)
            Enumerable.Range(1, 16).Select(i => (byte)i).ToArray(),

            // 3-key TripleDES (K1,K2,K3)
            Enumerable.Range(1, 24).Select(i => (byte)i).ToArray()
        };

        private static readonly byte[] IV =
        {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07
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
            Enumerable.Range(1, 7).Select(i => (byte)i).ToArray(),
            Enumerable.Range(1, 8).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 15).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 64).Select(i => (byte)i).ToArray()
        };

        [Theory]
        [MemberData(nameof(GetTestCases))]
        public void TripleDES_Encrypt_Decrypt_ReturnsExpected(
            byte[] key,
            TripleDesMode tdesMode,
            CipherMode mode,
            PaddingMode padding,
            byte[] plainText)
        {
            var tripleDes = new TripleDesCipher(tdesMode);

            var cipher = new ContextCipher.ContextCipher(
                key: key,
                mode: mode,
                padding: padding,
                algorithm: tripleDes,
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

        public static TheoryData<byte[], TripleDesMode, CipherMode, PaddingMode, byte[]> GetTestCases()
        {
            var data = new TheoryData<byte[], TripleDesMode, CipherMode, PaddingMode, byte[]>();

            foreach (var key in Keys)
            foreach (var tdesMode in Enum.GetValues(typeof(TripleDesMode)).Cast<TripleDesMode>())
            foreach (var mode in Modes)
            foreach (var padding in Paddings)
            foreach (var vector in TestData)
            {
                data.Add(key, tdesMode, mode, padding, vector);
            }

            return data;
        }
    }
}
