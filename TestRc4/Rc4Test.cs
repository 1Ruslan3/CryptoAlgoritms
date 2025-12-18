using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Rc4Algoritm;
using Xunit;

namespace TestRc4
{
    public class RC4CipherTests
    {
        private static readonly byte[][] Keys =
        {
            Encoding.ASCII.GetBytes("1234567890ABCDEF"),
            Encoding.ASCII.GetBytes("AnotherKey1234"),
            Enumerable.Range(0, 32).Select(i => (byte)i).ToArray()
        };

        private static readonly byte[][] TestData =
        {
            Array.Empty<byte>(),
            new byte[] { 0x01 },
            new byte[] { 1,2,3,4,5,6,7,8 },
            Enumerable.Range(0, 15).Select(i => (byte)i).ToArray(),
            Enumerable.Range(0, 64).Select(i => (byte)i).ToArray(),
            Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog")
        };

        [Theory]
        [MemberData(nameof(GetTestCases))]
        public void EncryptDecrypt(byte[] key, byte[] plainText)
        {
            var rc4 = new RC4Cipher(key);
          
            byte[] buffer = (byte[])plainText.Clone();
            rc4.InPlace(buffer); 

            rc4.Reset(key);
            rc4.InPlace(buffer); 

            Assert.Equal(plainText, buffer); 
        }

        [Theory]
        [MemberData(nameof(GetTestCases))]
        public async Task ProcessAsync(byte[] key, byte[] plainText)
        {
            var rc4 = new RC4Cipher(key);

            using var input = new MemoryStream(plainText);
            using var encrypted = new MemoryStream();
            await rc4.ProcessAsync(input, encrypted);

            byte[] cipherText = encrypted.ToArray();

            rc4.Reset(key);
            using var encryptedStream = new MemoryStream(cipherText);
            using var output = new MemoryStream();
            await rc4.ProcessAsync(encryptedStream, output);

            byte[] decrypted = output.ToArray();

            Assert.Equal(plainText, decrypted);
        }

        public static TheoryData<byte[], byte[]> GetTestCases()
        {
            var data = new TheoryData<byte[], byte[]>();

            foreach (var key in Keys)
                foreach (var plainText in TestData)
                    data.Add(key, plainText);

            return data;
        }
    }
}
