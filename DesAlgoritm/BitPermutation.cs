using System;

namespace DesAlgoritm
{
    public static class BitPermutation
    {
        public static void PermuteBitsInPlace(byte[] data, int[] positions)
        {
            if (positions == null)
                throw new ArgumentNullException(nameof(positions));
            if (data == null)
                throw new ArgumentNullException(nameof(data));

            int outBits = positions.Length;
            int totalBits = data.Length * 8;
            if (outBits > totalBits)
                throw new ArgumentException("Permutation table is larger than data bit length.");

            Span<byte> source = stackalloc byte[data.Length];
            data.CopyTo(source);

            for (int i = 0; i < outBits; i++)
            {
                int srcBitIndex = positions[i] - 1; 
                bool bit = GetBit(source, srcBitIndex);
                SetBit(data, i, bit);
            }
        }
        public static byte[] PermuteBits(byte[] input, int[] positions)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (positions == null)
                throw new ArgumentNullException(nameof(positions));

            int outBits = positions.Length;
            int outBytes = (outBits + 7) / 8;
            byte[] output = new byte[outBytes];

            for (int i = 0; i < outBits; i++)
            {
                int srcBitIndex = positions[i] - 1;
                bool bit = GetBit(input, srcBitIndex);
                SetBit(output, i, bit);
            }

            return output;
        }
        private static bool GetBit(ReadOnlySpan<byte> data, int bitIndex)
        {
            int bidx = bitIndex / 8;
            int bitInByte = 7 - (bitIndex % 8);
            return (data[bidx] & (1 << bitInByte)) != 0;
        }

        private static void SetBit(Span<byte> data, int bitIndex, bool val)
        {
            int bidx = bitIndex / 8;
            int bitInByte = 7 - (bitIndex % 8);
            if (val)
                data[bidx] |= (byte)(1 << bitInByte);
            else
                data[bidx] &= (byte)~(1 << bitInByte);
        }

        private static bool GetBit(byte[] data, int bitIndex)
        {
            int bidx = bitIndex / 8;
            int bitInByte = 7 - (bitIndex % 8);
            return (data[bidx] & (1 << bitInByte)) != 0;
        }

        private static void SetBit(byte[] data, int bitIndex, bool val)
        {
            int bidx = bitIndex / 8;
            int bitInByte = 7 - (bitIndex % 8);
            if (val)
                data[bidx] |= (byte)(1 << bitInByte);
            else
                data[bidx] &= (byte)~(1 << bitInByte);
        }
    }
}