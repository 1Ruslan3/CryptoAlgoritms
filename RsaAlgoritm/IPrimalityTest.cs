using System;
using System.Collections.Generic;
using System.Numerics;

namespace RsaAlgoritm
{
    public interface IPrimalityTest
    {
        bool IsPrime(BigInteger n);
    }
}