using System.Numerics;

namespace RsaAlgoritm
{
    public interface IProbabilisticPrimalityTest
    {
        bool IsProbablePrime(BigInteger n, double minProbability);
    }
}