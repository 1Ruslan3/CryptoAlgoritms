using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace DiffieHellman
{
    public class DiffieHellmanProtocol
    {
        public BigInteger P { get; }
        public BigInteger G { get; }
        private BigInteger _privateKey;
        public BigInteger PublicKey { get; private set; }

        public DiffieHellmanProtocol(BigInteger p, BigInteger g)
        {
            P = p;
            G = g;
            GenerateKeyPair();
        }

        private void GenerateKeyPair()
        {
            _privateKey = GenerateRandomBigInteger(256);
            PublicKey = BigInteger.ModPow(G, _privateKey, P);
        }

        public BigInteger ComputeSharedSecret(BigInteger otherPublicKey)
        {
            if (otherPublicKey <= 1 || otherPublicKey >= P - 1)
                throw new ArgumentException("Некорректный публичный ключ.");

            return BigInteger.ModPow(otherPublicKey, _privateKey, P);
        }

        public byte[] DeriveKey(BigInteger sharedSecret)
        {
            using SHA256 sha = SHA256.Create();
            return sha.ComputeHash(sharedSecret.ToByteArray());
        }

        private static BigInteger GenerateRandomBigInteger(int bits)
        {
            int bytes = (bits + 7) / 8;
            byte[] buffer = new byte[bytes];
            RandomNumberGenerator.Fill(buffer);
            buffer[^1] &= 0b0111_1111; 
            return new BigInteger(buffer);
        }

        public static BigInteger GeneratePrime(int bits)
        {
            while (true)
            {
                var candidate = GenerateRandomBigInteger(bits);
                if (candidate < 3) continue;
                if (candidate % 2 == 0) candidate++;

                if (IsProbablePrime(candidate, 20))
                    return candidate;
            }
        }

        private static bool IsProbablePrime(BigInteger n, int rounds)
        {
            if (n < 2) return false;
            if (n == 2 || n == 3) return true;
            if (n % 2 == 0) return false;

            BigInteger d = n - 1;
            int s = 0;
            while (d % 2 == 0)
            {
                d /= 2;
                s++;
            }

            for (int i = 0; i < rounds; i++)
            {
                BigInteger a = RandomInRange(2, n - 2);
                BigInteger x = BigInteger.ModPow(a, d, n);

                if (x == 1 || x == n - 1) continue;

                bool continueOuter = false;
                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, n);
                    if (x == n - 1)
                    {
                        continueOuter = true;
                        break;
                    }
                }

                if (continueOuter) continue;
                return false;
            }

            return true;
        }

        private static BigInteger RandomInRange(BigInteger min, BigInteger max)
        {
            BigInteger range = max - min + 1;
            int bytes = range.ToByteArray().Length;
            BigInteger result;
            byte[] buffer = new byte[bytes];

            do
            {
                RandomNumberGenerator.Fill(buffer);
                buffer[^1] &= 0b0111_1111;
                result = new BigInteger(buffer);
            }
            while (result >= range);

            return min + result;
        }
    }

}
