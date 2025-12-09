using System.Numerics;
using System.Text;

namespace RsaAlgoritm
{
    class Program
    {
        static void Main()
        {
            IPrimalityTest test = new FermatTest(20);


            var rsa = new RsaCipher(test, 256);

            var (n, e, d) = rsa.GetKeys();

            Console.WriteLine("RSA Keys:");
            Console.WriteLine($"n = {n}");
            Console.WriteLine($"e = {e}");
            Console.WriteLine($"d = {d}\n");

            // string text = "HELLO RSA";
            // BigInteger msg = new BigInteger(Encoding.UTF8.GetBytes(text), true, true);

            // BigInteger cipher = rsa.Encrypt(msg);
            // Console.WriteLine($"Encrypted: {cipher}");

            // BigInteger decrypted = rsa.Decrypt(cipher);
            // string result = Encoding.UTF8.GetString(decrypted.ToByteArray(true, true));
            // Console.WriteLine($"Decrypted: {result}\n");
            RsaCipher.FileProcessor files = new RsaCipher.FileProcessor(rsa);

            files.EncryptFile("input.txt", "encrypted.bin");
            files.DecryptFile("encrypted.bin", "decrypted.txt");

            
        

            if (WienerAttack.TryRecoverPrivateKey(e, n, out BigInteger crackedD))
                Console.WriteLine("ВИНЕР СРАБОТАЛ! d = " + crackedD);
            else
                Console.WriteLine("Атака Винера НЕ применима");
        }
    }
}