namespace Rc4Algoritm;

public sealed class Program
{
    public static void Main()
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("Sqwoz BAB");
        byte[] key = System.Text.Encoding.UTF8.GetBytes("secret");

        var rc4 = new RC4Cipher(key);
        rc4.InPlace(data);

        Console.WriteLine("Encrypted: " + BitConverter.ToString(data).Replace("-", ""));
        rc4.Reset(key);
        rc4.InPlace(data);
        Console.WriteLine("Decrypted: " + System.Text.Encoding.UTF8.GetString(data));
    }
}