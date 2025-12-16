using System.Text;
using ContextCipher;

namespace DesAlgoritm
{
    class Program
    {
        static void Main()
        {
            var des = new DesCipher();
            var deal = new DealCipher();
            var rijndael = new RijndaelAlgoritm.RijndaelCipher();
            var magenta = new MagentaAlgoritm.MagentaCipher();

            string inputFile  = "input.txt";
            string encryptedFile = "encrypted.bin";
            string decryptedFile = "decrypted.txt";

            byte[] key = Encoding.ASCII.GetBytes("1234567887654321"); 
            byte[] iv = Encoding.ASCII.GetBytes("1234567887654321");  

            var cipher = new ContextCipher.ContextCipher(
                key: key,
                mode: CipherMode.ECB,
                padding: PaddingMode.PKCS7,
                algorithm: deal,
                iv: iv);

            Console.WriteLine("Encrypting file...");
            cipher.EncryptFile(inputFile, encryptedFile);
            Console.WriteLine($"Encrypted to: {encryptedFile}");

            Console.WriteLine("Decrypting file...");
            cipher.DecryptFile(encryptedFile, decryptedFile);
            Console.WriteLine($"Decrypted to: {decryptedFile}");

            byte[] data = File.ReadAllBytes(decryptedFile);
            string text = Encoding.UTF8.GetString(data);
            Console.WriteLine(text);

            // string plaintext = "ABCDEFGHABCDEFGHHHHH";
            // byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
            // byte[] encrypted = cipher.Encrypt(plainBytes);
            // Console.WriteLine("Encrypted (hex): " + BitConverter.ToString(encrypted).Replace("-", ""));
            // byte[] decrypted = cipher.Decrypt(encrypted);
            // Console.WriteLine("Decrypted: " + Encoding.UTF8.GetString(decrypted));
        }
    }
}