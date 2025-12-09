using System;
using System.Collections.Generic;
using System.Numerics;

namespace RsaAlgoritm
{
    public class MillerRabinTest : FermatTest
    {
        private readonly double _probability;
        public MillerRabinTest(double probability, int fermatRounds = 5)
            : base(fermatRounds)
        {
            _probability = probability;
        }
        public new bool IsPrime(BigInteger n)
        {
            if (!base.IsPrime(n)) return false;
            if (n < 2 || n % 2 == 0) return n == 2;

            int rounds = (int)Math.Ceiling(
                Math.Log(1.0 / (1.0 - _probability)) / Math.Log(4.0));

            BigInteger d = n - 1;
            int r = 0;
            while ((d & 1) == 0)
            {
                d >>= 1;
                r++;
            }

            for (int i = 0; i < rounds; i++)
            {
                BigInteger a = RandomInRange(2, n - 2);
                BigInteger x = BigInteger.ModPow(a, d, n);

                if (x == 1 || x == n - 1) continue;

                bool composite = true;
                for (int j = 0; j < r - 1; j++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == n - 1)
                    {
                        composite = false;
                        break;
                    }
                }
                if (composite) return false;
            }
            return true;
        }
    }
}