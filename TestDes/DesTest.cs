using System;
using System.Linq;
using Xunit;
using ContextCipher;
using DesAlgoritm;

namespace TestDes
{
    public sealed class DesCipherTests
    {
        private static readonly byte[] Key =
        {
            0x13, 0x34, 0x57, 0x79,
            0x9B, 0xBC, 0xDF, 0xF1
        };

        private static readonly byte[] IV =
        {
            0x01, 0x23, 0x45, 0x67,
            0x89, 0xAB, 0xCD, 0xEF
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
            new byte[] { 1,2,3,4,5,6,7 },
            new byte[] { 1,2,3,4,5,6,7,8 },
            Enumerable.Range(0, 15).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 64).Select(i => (byte)i).ToArray()
        };

        [Theory]
        [MemberData(nameof(GetTestCases))]
        public void EncryptDecrypt(
            CipherMode mode,
            PaddingMode padding,
            byte[] plainText)
        {
            var des = new DesCipher();

            var cipher = new ContextCipher.ContextCipher(
                key: Key,
                mode: mode,
                padding: padding,
                algorithm: des,
                iv: IV);

            byte[] encrypted = cipher.Encrypt(plainText);
            byte[] decrypted = cipher.Decrypt(encrypted);

            if (padding == PaddingMode.ZeroPadding)
            {
                Assert.True(decrypted.Length >= plainText.Length);

                for (int i = 0; i < plainText.Length; i++)
                {
                    Assert.Equal(plainText[i], decrypted[i]);
                }
            }
            else
            {
                Assert.Equal(plainText, decrypted);
            }
        }

        // [Theory]
        // [MemberData(nameof(GetTestCases))]
        // public void EncryptDecrypt_File(
        //     CipherMode mode,
        //     PaddingMode padding,
        //     byte[] plainText)
        // {
        //     var des = new DesCipher();

        //     var cipher = new ContextCipher.ContextCipher(
        //         key: Key,
        //         mode: mode,
        //         padding: padding,
        //         algorithm: des,
        //         iv: IV);

        //     string inputPath = Path.GetTempFileName();
        //     string encryptedPath = Path.GetTempFileName();
        //     string decryptedPath = Path.GetTempFileName();

        //     try
        //     {
        //         File.WriteAllBytes(inputPath, plainText);

        //         cipher.EncryptFile(inputPath, encryptedPath);

        //         cipher.DecryptFile(encryptedPath, decryptedPath);

        //         byte[] decrypted = File.ReadAllBytes(decryptedPath);

        //         if (padding == PaddingMode.PKCS7)
        //         {
        //             Assert.True(decrypted.Length >= plainText.Length);

        //             for (int i = 0; i < plainText.Length; i++)
        //             {
        //                 Assert.Equal(plainText[i], decrypted[i]);
        //             }
        //         }
        //         else
        //         {
        //             Assert.Equal(plainText, decrypted);
        //         }
        //     }
        //     finally
        //     {
        //         File.Delete(inputPath);
        //         File.Delete(encryptedPath);
        //         File.Delete(decryptedPath);
        //     }
        // }

        public static TheoryData<CipherMode, PaddingMode, byte[]> GetTestCases()
        {
            var data = new TheoryData<CipherMode, PaddingMode, byte[]>();

            foreach (var mode in Modes)
            foreach (var padding in Paddings)
            foreach (var vector in TestData)
            {
                data.Add(mode, padding, vector);
            }

            return data;
        }
    }
}
