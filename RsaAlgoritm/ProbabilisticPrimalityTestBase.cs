using System.Numerics;

namespace RsaAlgoritm
{
    public abstract class ProbabilisticPrimalityTestBase : IProbabilisticPrimalityTest
    {
        protected readonly NumberTheoryService NTS;

        protected ProbabilisticPrimalityTestBase(NumberTheoryService service)
        {
            NTS = service ?? throw new ArgumentNullException(nameof(service));
        }

        public bool IsProbablePrime(BigInteger n, double minProbability)
        {
            if (minProbability < 0.5 || minProbability >= 1)
                throw new ArgumentException("minProbability must be in [0.5, 1).");

            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n.IsEven) return false;

            // Количество раундов: p = 1 - (1/2)^k → k = ceil(log2(1/(1-p)))
            int k = (int)Math.Ceiling(Math.Log(1.0 / (1 - minProbability), 2));

            for (int i = 0; i < k; i++)
            {
                if (!RunIteration(n))
                    return false;  // составное
            }

            return true; // вероятно простое
        }

        /// <summary>
        /// Одна итерация вероятностного теста.
        /// Потомок должен вернуть false, если обнаружена составность n.
        /// </summary>
        protected abstract bool RunIteration(BigInteger n);

        /// Выбор случайного числа
        protected BigInteger RandomInRange(BigInteger min, BigInteger max)
        {
            if (min > max) throw new ArgumentException();

            BigInteger range = max - min + 1;
            int bytes = range.GetByteCount();
            BigInteger r;

            var rng = System.Security.Cryptography.RandomNumberGenerator.Create();

            do
            {
                byte[] buf = new byte[bytes];
                rng.GetBytes(buf);
                r = new BigInteger(buf, isUnsigned: true, isBigEndian: false);
            }
            while (r >= range);

            return min + r;
        }
    }

    public sealed class FermatPrimalityTest : ProbabilisticPrimalityTestBase
    {
        public FermatPrimalityTest(NumberTheoryService nts) : base(nts) { }

        protected override bool RunIteration(BigInteger n)
        {
            BigInteger a = RandomInRange(2, n - 2);
            return NTS.ModExp.ModPow(a, n - 1, n) == 1;
        }
    }

    public sealed class SolovayStrassenPrimalityTest : ProbabilisticPrimalityTestBase
    {
        public SolovayStrassenPrimalityTest(NumberTheoryService nts) : base(nts) { }

        protected override bool RunIteration(BigInteger n)
        {
            BigInteger a = RandomInRange(2, n - 1);
            int jac = NTS.Jacobi.JacobiSymbol(a, n);
            if (jac == 0) return false;

            BigInteger t = NTS.ModExp.ModPow(a, (n - 1) / 2, n);

            // t должно быть либо 1, либо n−1
            BigInteger jacMod = jac < 0 ? n - 1 : 1;

            return t == jacMod;
        }
    }

    public sealed class MillerRabinPrimalityTest : ProbabilisticPrimalityTestBase
    {
        public MillerRabinPrimalityTest(NumberTheoryService nts) : base(nts) { }

        protected override bool RunIteration(BigInteger n)
        {
            // n - 1 = 2^s * d
            BigInteger d = n - 1;
            int s = 0;
            while ((d & 1) == 0)
            {
                d >>= 1;
                s++;
            }

            BigInteger a = RandomInRange(2, n - 2);
            BigInteger x = NTS.ModExp.ModPow(a, d, n);

            if (x == 1 || x == n - 1)
                return true;

            for (int r = 1; r < s; r++)
            {
                x = NTS.ModExp.ModPow(x, 2, n);
                if (x == n - 1)
                    return true;
                if (x == 1)
                    return false; // составное
            }

            return false; // составное
        }
    }


}