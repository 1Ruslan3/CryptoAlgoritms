using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;

namespace RsaAlgoritm
{
    public class RsaCipher
    {
        #region nested Classes
        public class KeyGenerator
        {
            #region Fields and Properties
            private readonly IPrimalityTest _primalityTest;
            private readonly int _bits;
            #endregion

            #region Constructors
            public KeyGenerator(IPrimalityTest test, int bits)
            {
                if (bits < 128)
                    throw new ArgumentException("Bit length must be >= 128");

                _primalityTest = test;
                _bits = bits;
            }
            #endregion

            #region Methods
            public (BigInteger n, BigInteger e, BigInteger d) GenerateKeyPair()
            {
                while (true)
                {
                    BigInteger p = GeneratePrime(_bits / 2);
                    BigInteger q = GeneratePrime(_bits / 2);

                    if (p == q) continue;

                    if (BigInteger.Abs(p - q) < (BigInteger.One << (_bits / 3)))
                        continue;

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

                    if (WienerAttack.TryRecoverPrivateKey(e, n, out _))
                        continue;

                    return (n, e, d);
                }
            }
            #endregion

            #region Helper Methods
            private BigInteger GeneratePrime(int bits)
            {
                while (true)
                {
                    BigInteger candidate = RandomBigInteger(bits) | 1;
                    if (candidate < 3)
                        continue;

                    if (_primalityTest.IsPrime(candidate))
                        return candidate;
                }
            }

            private static BigInteger RandomBigInteger(int bits)
            {
                int bytesLen = (bits + 7) / 8;
                byte[] bytes = new byte[bytesLen];
                RandomNumberGenerator.Fill(bytes);

                int excessBits = bytesLen * 8 - bits;
                bytes[0] &= (byte)(0xFF >> excessBits);
                bytes[0] |= (byte)(1 << (7 - excessBits));

                return new BigInteger(bytes, true, true);
            }

            private static BigInteger ModInverse(BigInteger a, BigInteger m)
            {
                BigInteger x, y;
                ExtendedGcd(a, m, out x, out y);
                return (x % m + m) % m;
            }

            private static BigInteger ExtendedGcd(BigInteger a, BigInteger b, out BigInteger x, out BigInteger y)
            {
                if (b == 0)
                {
                    x = 1; y = 0; return a;
                }

                BigInteger gcd = ExtendedGcd(b, a % b, out BigInteger x1, out BigInteger y1);
                x = y1;
                y = x1 - (a / b) * y1;
                return gcd;
            }
            #endregion
        }
        public class FileProcessor
        {
            #region Fields and Properties
            private readonly RsaCipher _rsa;
            #endregion

            #region Constructors
            public FileProcessor(RsaCipher rsa)
            {
                _rsa = rsa;
            }
            #endregion

            #region Methods
            public void EncryptFile(string inputPath, string outputPath)
            {
                byte[] data = File.ReadAllBytes(inputPath);

                BigInteger n = _rsa._n;
                int blockSize = n.GetByteCount() - 1;

                using FileStream fs = new FileStream(outputPath, FileMode.Create);
                using BinaryWriter bw = new BinaryWriter(fs);

                for (int i = 0; i < data.Length; i += blockSize)
                {
                    int len = Math.Min(blockSize, data.Length - i);
                    byte[] block = new byte[len];
                    Array.Copy(data, i, block, 0, len);

                    BigInteger m = new BigInteger(block, true, true);
                    BigInteger c = _rsa.Encrypt(m);

                    byte[] cryptBlock = c.ToByteArray(true, true);

                    bw.Write(len);                 
                    bw.Write(cryptBlock.Length);  
                    bw.Write(cryptBlock);        
                }
            }

            public void DecryptFile(string inputPath, string outputPath)
            {
                using FileStream fs = new FileStream(inputPath, FileMode.Open);
                using BinaryReader br = new BinaryReader(fs);
                using FileStream outFs = new FileStream(outputPath, FileMode.Create);

                while (fs.Position < fs.Length)
                {
                    int plainLen = br.ReadInt32();
                    int cryptLen = br.ReadInt32();
                    byte[] cryptBlock = br.ReadBytes(cryptLen);

                    BigInteger c = new BigInteger(cryptBlock, true, true);
                    BigInteger m = _rsa.Decrypt(c);

                    byte[] plainBlock = m.ToByteArray(true, true);

                    if (plainBlock.Length > plainLen)
                    {
                        byte[] fixedBlock = new byte[plainLen];
                        Array.Copy(plainBlock, plainBlock.Length - plainLen, fixedBlock, 0, plainLen);
                        outFs.Write(fixedBlock);
                    }
                    else if (plainBlock.Length < plainLen)
                    {
                        byte[] fixedBlock = new byte[plainLen];
                        int offset = plainLen - plainBlock.Length;
                        Array.Copy(plainBlock, 0, fixedBlock, offset, plainBlock.Length);
                        outFs.Write(fixedBlock);
                    }
                    else
                    {
                        outFs.Write(plainBlock);
                    }
                }
            }
            #endregion
        }
        #endregion

        #region Fields and Properties
        private BigInteger _n, _e, _d;
        public KeyGenerator Generator { get; }
        #endregion

        #region Constructors
        public RsaCipher(IPrimalityTest test, int bitLength)
        {
            Generator = new KeyGenerator(test, bitLength);
            GenerateNewKeys();
        }
        #endregion

        #region Methods
        public void GenerateNewKeys()
        {
            (_n, _e, _d) = Generator.GenerateKeyPair();
        }
        public BigInteger Encrypt(BigInteger m) => BigInteger.ModPow(m, _e, _n);
        public BigInteger Decrypt(BigInteger c) => BigInteger.ModPow(c, _d, _n);
        public (BigInteger n, BigInteger e, BigInteger d) GetKeys() => (_n, _e, _d);
        #endregion
    }
}
