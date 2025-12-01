using System;
using System.Text;
using ContextCipher;

namespace MagentaAlgoritm
{
    class Program
    {
        public static void Main()
        {
            byte[] key = Encoding.ASCII.GetBytes("1234567812345678"); 
            byte[] iv = Encoding.ASCII.GetBytes("12345678abzvxcds");  
            var magenta = new MagentaCipher();
            magenta.Initialize(key);

            var cipher = new ContextCipher.ContextCipher(
                key: key,
                mode: CipherMode.CBC,
                padding: PaddingMode.PKCS7,
                algorithm: magenta,
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