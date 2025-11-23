using System.Text;
using ContextCipher;

namespace DesAlgoritm
{
    class Program
    {
        static void Main()
        {
            var des = new TripleDesCipher(mode: TripleDesMode.EEE);

            byte[] key = Encoding.ASCII.GetBytes("1234567812345678"); 
            byte[] iv = Encoding.ASCII.GetBytes("12345678");  

            var cipher = new ContextCipher.ContextCipher(
                key: key,
                mode: CipherMode.ECB,
                padding: PaddingMode.ANSI_X923,
                algorithm: des,
                iv: iv);
                
            string plaintext = "ABCDEFGHABCDEFGHHHHH";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] encrypted = cipher.Encrypt(plainBytes);
            Console.WriteLine("Encrypted (hex): " + BitConverter.ToString(encrypted).Replace("-", ""));
            byte[] decrypted = cipher.Decrypt(encrypted);
            Console.WriteLine("Decrypted: " + Encoding.UTF8.GetString(decrypted));
        }
    }
}