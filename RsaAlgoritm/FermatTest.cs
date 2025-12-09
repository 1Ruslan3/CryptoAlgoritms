using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;

namespace RsaAlgoritm
{
        public class FermatTest : IPrimalityTest
    {
        private readonly int _rounds;

        public FermatTest(int rounds = 10)
        {
            _rounds = rounds;
        }

        public bool IsPrime(BigInteger n)
        {
            if (n < 4) return n == 2 || n == 3;
            if (n % 2 == 0) return false;

            for (int i = 0; i < _rounds; i++)
            {
                BigInteger a = RandomInRange(2, n - 2);
                if (BigInteger.ModPow(a, n - 1, n) != 1)
                    return false;
            }
            return true;
        }

        protected static BigInteger RandomInRange(BigInteger min, BigInteger max)
        {
            BigInteger range = max - min + 1;
            int bits = range.GetByteCount() * 8;

            BigInteger x;
            do
            {
                byte[] data = new byte[(bits + 7) / 8];
                RandomNumberGenerator.Fill(data);
                x = new BigInteger(data, true, true);
            } while (x >= range);

            return min + x;
        }
    }
}