using System.Text;

namespace DesAlgoritm
{
    class Program
    {
        static void Main()
        {
            var des = new DesCipher();

            byte[] key = Encoding.ASCII.GetBytes("12345678"); 
            byte[] iv = Encoding.ASCII.GetBytes("ABCDEFGH");  

            var cipher = new BlockCipher(
                key: key,
                mode: CipherMode.CFB,
                padding: PaddingMode.PKCS7,
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

