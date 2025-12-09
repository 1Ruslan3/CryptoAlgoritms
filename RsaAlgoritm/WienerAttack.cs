using System;
using System.Collections.Generic;
using System.Numerics;

namespace RsaAlgoritm
{
    public static class WienerAttack
    {
        public static bool TryRecoverPrivateKey(BigInteger e, BigInteger n, out BigInteger d)
        {
            d = 0;
            var frac = ContinuedFraction(e, n);

            foreach (var kOverD in Convergents(frac))
            {
                BigInteger k = kOverD.Item1;
                BigInteger dCandidate = kOverD.Item2;

                if (k == 0) continue;

                BigInteger phiCandidate = (e * dCandidate - 1) / k;
                BigInteger b = n - phiCandidate + 1;

                BigInteger delta = b * b - 4 * n;
                if (delta < 0) continue;

                BigInteger sqrt = IntegerSqrt(delta);
                if (sqrt * sqrt != delta) continue;

                d = dCandidate;
                return true; 
            }

            return false;
        }

        private static List<BigInteger> ContinuedFraction(BigInteger a, BigInteger b)
        {
            List<BigInteger> cf = new List<BigInteger>();
            while (b != 0)
            {
                cf.Add(a / b);
                (a, b) = (b, a % b);
            }
            return cf;
        }

        private static IEnumerable<(BigInteger, BigInteger)> Convergents(List<BigInteger> cf)
        {
            BigInteger pPrev = 1, p = cf[0];
            BigInteger qPrev = 0, q = 1;

            yield return (p, q);

            for (int i = 1; i < cf.Count; i++)
            {
                BigInteger pNext = cf[i] * p + pPrev;
                BigInteger qNext = cf[i] * q + qPrev;

                yield return (pNext, qNext);

                pPrev = p;
                qPrev = q;
                p = pNext;
                q = qNext;
            }
        }

        private static BigInteger IntegerSqrt(BigInteger n)
        {
            BigInteger x = n;
            BigInteger y = (x + 1) >> 1;
            while (y < x)
            {
                x = y;
                y = (x + n / x) >> 1;
            }
            return x;
        }
    }
}