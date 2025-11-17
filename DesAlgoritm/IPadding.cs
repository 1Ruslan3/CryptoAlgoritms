namespace DesAlgoritm
{
    public interface IPadding
    {
        byte[] ApplyPadding(byte[] data, int blockSize);
        byte[] RemovePadding(byte[] data, int blockSize);
    }
}