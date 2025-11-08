using System.Collections;

namespace DesAlgoritm
{
    public static class BitPermutation
    {
        public static byte[] PermuteBits(byte[] input, int[] positions)
        {
            if (positions == null) throw new ArgumentNullException(nameof(positions));
            int outBits = positions.Length;
            int outBytes = (outBits + 7) / 8;
            byte[] output = new byte[outBytes];

            for (int i = 0; i < positions.Length; i++)
            {
                int srcLogical = positions[i]; 
                bool bit = GetBit(input, srcLogical);
                int destLogical = i + 1;
                SetBit(output, destLogical, bit);
            }

            return output;
        }

        private static bool GetBit(byte[] data, int logical)
        {
            int bidx = (logical - 1) / 8;
            int bitInByte = 7 - ((logical - 1) % 8);
            if (bidx < 0 || bidx >= data.Length) return false;
            return (data[bidx] & (1 << bitInByte)) != 0;
        }

        private static void SetBit(byte[] data, int logical, bool val)
        {
            int bidx = (logical - 1) / 8;
            int bitInByte = 7 - ((logical - 1) % 8);
            if (bidx < 0 || bidx >= data.Length) return;
            if (val)
                data[bidx] |= (byte)(1 << bitInByte);
            else
                data[bidx] &= (byte)~(1 << bitInByte);
        }
    }
}

