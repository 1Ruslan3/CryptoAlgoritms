using System.Numerics;

namespace RsaAlgoritm
{
    public class RSAService
    {
        public enum PrimalityTest
        {
            MillerRabin
        }

        public class KeyGenerator
        {
            private readonly PrimalityTest _test;
            private readonly double _prob;
            private readonly int _bits;
            private readonly Random _rnd = new Random();

            public KeyGenerator(PrimalityTest test, double prob, int bits)
            {
                if (prob < 0.5 || prob >= 1)
                    throw new ArgumentException("Probability must be in [0.5, 1)");
                if (bits < 64)
                    throw new ArgumentException("Bit length must be >= 64");

                _test = test;
                _prob = prob;
                _bits = bits;
            }

            public (BigInteger n, BigInteger e, BigInteger d) GenerateKeyPair()
            {
                BigInteger p, q;

                do
                {
                    p = GeneratePrime(_bits / 2);
                    q = GeneratePrime(_bits / 2);
                } while (p == q || BigInteger.Abs(p - q) < (BigInteger.One << (_bits / 3)));

                BigInteger n = p * q;
                BigInteger phi = (p - 1) * (q - 1);

                BigInteger e = 65537;
                if (BigInteger.GreatestCommonDivisor(e, phi) != 1)
                {
                    e = 3;
                    while (BigInteger.GreatestCommonDivisor(e, phi) != 1)
                        e += 2;
                }

                BigInteger d = ModInverse(e, phi);

                if (d < BigInteger.Pow(n, 1 / 4))
                    return GenerateKeyPair();

                return (n, e, d);
            }

            private BigInteger GeneratePrime(int bits)
            {
                BigInteger prime;

                do
                {
                    prime = RandomBigIntegerBytes(bits) | 1;
                } while (!IsProbablePrime(prime));

                return prime;
            }

            private BigInteger RandomBigIntegerBytes(int bits)
            {
                int bytesLength = (bits + 7) / 8;
                byte[] bytes = new byte[bytesLength];
                _rnd.NextBytes(bytes);

                int extraBits = bytesLength * 8 - bits;
                bytes[0] &= (byte)(0xFF >> extraBits);
                bytes[0] |= (byte)(1 << (7 - extraBits));

                return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
            }

            private bool IsProbablePrime(BigInteger n)
            {
                if (n < 2) return false;
                if (n == 2 || n == 3) return true;
                if (n % 2 == 0) return false;

                int rounds = (int)Math.Ceiling(Math.Log(1.0 / (1 - _prob), 2));
                BigInteger d = n - 1;
                int r = 0;
                while ((d & 1) == 0) { d >>= 1; r++; }

                for (int i = 0; i < rounds; i++)
                {
                    BigInteger a = RandomInRange(2, n - 2);
                    BigInteger x = BigInteger.ModPow(a, d, n);
                    if (x == 1 || x == n - 1) continue;

                    bool composite = true;
                    for (int j = 0; j < r - 1; j++)
                    {
                        x = BigInteger.ModPow(x, 2, n);
                        if (x == n - 1) { composite = false; break; }
                    }
                    if (composite) return false;
                }
                return true;
            }

            private BigInteger RandomInRange(BigInteger min, BigInteger max)
            {
                BigInteger diff = max - min + 1;
                int bits = (int)Math.Ceiling(BigInteger.Log(diff, 2));
                BigInteger x;
                do
                {
                    x = RandomBigIntegerBytes(bits);
                } while (x >= diff);
                return min + x;
            }

            private BigInteger ModInverse(BigInteger a, BigInteger m)
            {
                BigInteger m0 = m, x0 = 0, x1 = 1;
                while (a > 1)
                {
                    BigInteger q = a / m;
                    BigInteger t = m;
                    m = a % m;
                    a = t;

                    t = x0;
                    x0 = x1 - q * x0;
                    x1 = t;
                }
                if (x1 < 0) x1 += m0;
                return x1;
            }
        }

        private BigInteger _n, _e, _d;
        public KeyGenerator Generator { get; }

        public RSAService(PrimalityTest test, double minProbability, int bitLength)
        {
            Generator = new KeyGenerator(test, minProbability, bitLength);
            GenerateNewKeys();
        }

        public void GenerateNewKeys()
        {
            (_n, _e, _d) = Generator.GenerateKeyPair();
        }

        public BigInteger Encrypt(BigInteger m) => BigInteger.ModPow(m, _e, _n);
        public BigInteger Decrypt(BigInteger c) => BigInteger.ModPow(c, _d, _n);

        public (BigInteger n, BigInteger e, BigInteger d) GetKeys() => (_n, _e, _d);
    }

    class Program
    {
        static void Main()
        {
            var rsa = new RSAService(
                RSAService.PrimalityTest.MillerRabin,
                minProbability: 0.99,
                bitLength: 256
            );

            var (n, e, d) = rsa.GetKeys();

            Console.WriteLine("RSA keys generated:");
            Console.WriteLine($"n = {n}");
            Console.WriteLine($"e = {e}");
            Console.WriteLine($"d = {d}\n");

            string text = "HELLO RSA";
            BigInteger msg = new BigInteger(System.Text.Encoding.UTF8.GetBytes(text), true, true);

            BigInteger cipher = rsa.Encrypt(msg);
            Console.WriteLine($"Encrypted: {cipher}");

            BigInteger decrypted = rsa.Decrypt(cipher);
            string result = System.Text.Encoding.UTF8.GetString(
                decrypted.ToByteArray(isUnsigned: true, isBigEndian: true));

            Console.WriteLine($"Decrypted: {result}");
        }
    }
}
