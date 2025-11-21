namespace Rc4Algoritm;

public class RC4Cipher
{
    private readonly byte[] S = new byte[256];
    private int x = 0;
    private int y = 0;

    public RC4Cipher(byte[] key)
    {
        Initialize(key);
    }

    private void Initialize(byte[] key)
    {
        for (int i = 0; i < 256; i++)
            S[i] = (byte)i;

        int j = 0;

        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + key[i % key.Length]) & 255;
            Swap(i, j);
        }
    }

    private void Swap(int i, int j)
    {
        byte t = S[i];
        S[i] = S[j];
        S[j] = t;
    }

    private byte NextByte()
    {
        x = (x + 1) & 255;
        y = (y + S[x]) & 255;
        Swap(x, y);
        return S[(S[x] + S[y]) & 255];
    }

    public void InPlace(Span<byte> buffer)
    {
        for (int i = 0; i < buffer.Length; i++)
        {
            buffer[i] ^= NextByte();
        }
    }

    public async Task ProcessAsync(
        Stream input,
        Stream output,
        int bufferSize = 8192,
        CancellationToken cancellationToken = default)
    {
        byte[] buffer = new byte[bufferSize];
        int bytesRead;

        while ((bytesRead = await input.ReadAsync(buffer, 0, buffer.Length, cancellationToken)) > 0)
        { 
            InPlace(buffer.AsSpan(0, bytesRead));

            await output.WriteAsync(buffer, 0, bytesRead, cancellationToken);
        }
    }

    public void Reset(byte[] key)
    {
        for (int i = 0; i < 256; i++)
            S[i] = (byte)i;

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] +  key[i % key.Length]) & 255;
            Swap(i, j);
        }

        x = 0;
        y = 0;
    }
}
