using System.Text;
namespace Rc4Algoritm;

public sealed class Program
{
    public static async Task Main()
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("Sqwoz BAB");
        byte[] key = System.Text.Encoding.UTF8.GetBytes("secret"); 

        var rc4 = new RC4Cipher(key);
        // rc4.InPlace(data);

        // Console.WriteLine("Encrypted: " + BitConverter.ToString(data).Replace("-", ""));
        // rc4.Reset(key);
        // rc4.InPlace(data);
        // Console.WriteLine("Decrypted: " + System.Text.Encoding.UTF8.GetString(data)); 
        using var inputEncrypt = new MemoryStream(data);
        using var encryptedStream = new MemoryStream();

        await rc4.ProcessAsync(inputEncrypt, encryptedStream);

        byte[] encryptedData = encryptedStream.ToArray();
        Console.WriteLine("Encrypted: " + BitConverter.ToString(encryptedData));

        rc4.Reset(key);

        using var inputDecrypt = new MemoryStream(encryptedData);
        using var decryptedStream = new MemoryStream();

        await rc4.ProcessAsync(inputDecrypt, decryptedStream);

        byte[] decryptedData = decryptedStream.ToArray();
        string decryptedText = Encoding.UTF8.GetString(decryptedData);

        Console.WriteLine("Decrypted: " + decryptedText);
    }
}