using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace DiffieHellman
{
    public class Program
    {
        public static void Main()
        {
            BigInteger p = DiffieHellmanProtocol.GeneratePrime(256);
            BigInteger g = 5;

            var alice = new DiffieHellmanProtocol(p, g);
            var bob = new DiffieHellmanProtocol(p, g);

            BigInteger aliceSecret = alice.ComputeSharedSecret(bob.PublicKey);
            BigInteger bobSecret = bob.ComputeSharedSecret(alice.PublicKey);

            byte[] keyA = alice.DeriveKey(aliceSecret);
            byte[] keyB = bob.DeriveKey(bobSecret);

            Console.WriteLine("Alice key: " + BitConverter.ToString(keyA));
            Console.WriteLine("Bob key:   " + BitConverter.ToString(keyB));
        }
    }
}