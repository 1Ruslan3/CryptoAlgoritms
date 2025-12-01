// using System.Numerics;

// namespace RsaAlgoritm
// {
//     class Program
//     {
//         public static void Main()
//         {
//             var nts = new NumberTheoryService();

//             IProbabilisticPrimalityTest fermat = new FermatPrimalityTest(nts); 
//             IProbabilisticPrimalityTest ss = new SolovayStrassenPrimalityTest(nts);
//             IProbabilisticPrimalityTest mr = new MillerRabinPrimalityTest(nts);

//             BigInteger n = BigInteger.Parse("170141183460469231731687303715884105727"); // пример простого

//             Console.WriteLine(fermat.IsProbablePrime(n, 0.999));
//             Console.WriteLine(ss.IsProbablePrime(n, 0.999));
//             Console.WriteLine(mr.IsProbablePrime(n, 0.99999));
//         }
//     }
// }