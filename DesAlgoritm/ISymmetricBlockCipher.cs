namespace DesAlgoritm
{
    public interface ISymmetricBlockCipher
    {
        byte[] Encrypt(byte[] inputBlock);

        byte[] Decrypt(byte[] inputBlock);

    }
}