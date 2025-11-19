namespace Rc4Algoritm;

public sealed class Program
{
    public static void Main()
    {
        byte[] data = System.Text.Encoding.UTF8.GetBytes("Sqwoz bab");
        byte[] key  = System.Text.Encoding.UTF8.GetBytes("secret");

        var rc4 = new RC4(key);

        rc4.ProcessInPlace(data); 
        Console.WriteLine("Encrypted: " + BitConverter.ToString(data).Replace("-", ""));

        var rc4dec = new RC4(key);
        
        rc4dec.ProcessInPlace(data); 
        Console.WriteLine("Decrypted: " + System.Text.Encoding.UTF8.GetString(data));
    }
}