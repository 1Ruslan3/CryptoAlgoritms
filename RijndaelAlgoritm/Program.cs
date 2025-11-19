using System.Text;
using ContextCipher;

namespace RijndaelAlgoritm
{
    class Program
    {
        static void Main()
        {
            byte[] key = Encoding.ASCII.GetBytes("12345678"); 
            byte[] iv = Encoding.ASCII.GetBytes("12345678ABCDEFGH");  
            var rijndael = new RijndaelCipher(128);

            var cipher = new ContextCipher.ContextCipher(
                key: key,
                mode: CipherMode.CBC,
                padding: PaddingMode.ANSI_X923,
                algorithm: rijndael,
                iv: iv);
                
            string plaintext = "ABCDEFGHABCDEFGHHHHHwfvdsfewfvr";
            byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] encrypted = cipher.Encrypt(plainBytes);
            Console.WriteLine("Encrypted (hex): " + BitConverter.ToString(encrypted).Replace("-", ""));
            byte[] decrypted = cipher.Decrypt(encrypted);
            Console.WriteLine("Decrypted: " + Encoding.UTF8.GetString(decrypted));
        }
    }
}