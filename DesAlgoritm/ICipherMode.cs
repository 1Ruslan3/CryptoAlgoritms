namespace DesAlgoritm
{
    public interface ICipherMode
    {
        void EncryptBlock(
            CipherMode mode,
            byte[] input,
            byte[] output,
            Func<byte[], byte[]> encryptFunc);

        void DecryptBlock(
            CipherMode mode,
            byte[] input,
            byte[] output,
            Func<byte[], byte[]> encryptFunc,
            Func<byte[], byte[]> decryptFunc);

        void Reset();
    }
}
