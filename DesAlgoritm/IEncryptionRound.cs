namespace DesAlgoritm
{
    public interface IEncryptionRound
    {
        byte[] EncryptionRound(byte[] inputBlock, byte[] key);
    }
}