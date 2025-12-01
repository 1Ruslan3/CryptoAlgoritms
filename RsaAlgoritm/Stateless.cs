using System.Numerics;
using System.Text;

namespace RsaAlgoritm
{
    // --- Интерфейсы компонент ---
    public interface ILegendre
    {
        /// <summary>Возвращает символ Лежандра (a|p): -1, 0 или +1. p должен быть нечётным простым.</summary>
        int LegendreSymbol(BigInteger a, BigInteger p);
    }

    public interface IJacobi
    {
        /// <summary>Возвращает символ Якоби (a|n): -1, 0 или +1. n должно быть нечётным положительным.</summary>
        int JacobiSymbol(BigInteger a, BigInteger n);
    }

    public interface IGcd
    {
        BigInteger Gcd(BigInteger a, BigInteger b);
    }

    public interface IExtendedGcd
    {
        /// <summary>Возвращает (g, x, y) такие, что g = gcd(a,b) и a*x + b*y = g</summary>
        (BigInteger g, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b);
    }

    public interface IModExp
    {
        /// <summary>Вычисляет base^exp mod mod. Если exp < 0, пытается использовать обратный элемент (если существует).</summary>
        BigInteger ModPow(BigInteger @base, BigInteger exp, BigInteger mod);
    }

    // --- Реализации компонент (stateless, без полей) ---
    public sealed class LegendreComponent : ILegendre
    {
        private readonly IModExp _modExp;
        public LegendreComponent(IModExp modExp) => _modExp = modExp ?? throw new ArgumentNullException(nameof(modExp));

        public int LegendreSymbol(BigInteger a, BigInteger p)
        {
            if (p <= 2 || p.IsEven) throw new ArgumentException("p must be an odd prime (>=3) for Legendre symbol.");

            a %= p;
            if (a.IsZero) return 0;

            // по критерию Эйлера: a^{(p-1)/2} mod p == 1 -> 1, == p-1 -> -1
            BigInteger t = _modExp.ModPow(a, (p - 1) / 2, p);
            if (t.IsZero) return 0;
            if (t == 1) return 1;
            if (t == p - 1) return -1;
            // Теоретически не должно случаться
            throw new InvalidOperationException("Unexpected value in Legendre calculation.");
        }
    }

    public sealed class JacobiComponent : IJacobi
    {
        // реализован итеративно без факторизации n
        public int JacobiSymbol(BigInteger a, BigInteger n)
        {
            if (n <= 0 || n.IsEven) throw new ArgumentException("n must be positive odd integer for Jacobi symbol");

            a %= n;
            if (a.IsZero) return 0;
            int result = 1;

            BigInteger aa = a;
            BigInteger nn = n;

            while (aa != 0)
            {
                // извлечём фактор 2^e
                int e = 0;
                while (aa.IsEven)
                {
                    aa >>= 1;
                    e++;
                }

                if (e != 0)
                {
                    // при каждом факторе 2 учитываем (2|n)
                    // (2|n) = 1 если n % 8 == 1 или 7, = -1 если n % 8 == 3 или 5
                    int nMod8 = (int)(nn % 8);
                    if (nMod8 == 3 || nMod8 == 5)
                        result = -result;
                }

                // теперь применяем взаимность
                // если оба ≡ 3 (mod 4), то меняем знак
                if ((aa % 4 == 3) && (nn % 4 == 3))
                    result = -result;

                // swap aa и nn, aa <- aa mod nn
                BigInteger temp = aa;
                aa = nn % temp;
                nn = temp;
            }

            return (nn == 1) ? result : 0;
        }
    }

    public sealed class GcdComponent : IGcd
    {
        public BigInteger Gcd(BigInteger a, BigInteger b)
        {
            a = BigInteger.Abs(a);
            b = BigInteger.Abs(b);
            while (!b.IsZero)
            {
                BigInteger r = a % b;
                a = b;
                b = r;
            }
            return a;
        }
    }

    public sealed class ExtendedGcdComponent : IExtendedGcd
    {
        // Итеративный расширенный алгоритм Евклида (без рекурсии)
        public (BigInteger g, BigInteger x, BigInteger y) ExtendedGcd(BigInteger a, BigInteger b)
        {
            BigInteger old_r = a, r = b;
            BigInteger old_s = BigInteger.One, s = BigInteger.Zero;
            BigInteger old_t = BigInteger.Zero, t = BigInteger.One;

            while (!r.IsZero)
            {
                BigInteger q = old_r / r;

                BigInteger tmp = old_r - q * r;
                old_r = r; r = tmp;

                tmp = old_s - q * s;
                old_s = s; s = tmp;

                tmp = old_t - q * t;
                old_t = t; t = tmp;
            }

            // теперь old_r = gcd, и old_s * a + old_t * b = old_r
            return (old_r, old_s, old_t);
        }
    }

    public sealed class ModExpComponent : IModExp
    {
        private readonly IExtendedGcd _extGcd;

        public ModExpComponent(IExtendedGcd extGcd) => _extGcd = extGcd ?? throw new ArgumentNullException(nameof(extGcd));

        public BigInteger ModPow(BigInteger @base, BigInteger exp, BigInteger mod)
        {
            if (mod <= 0) throw new ArgumentException("mod must be positive.");
            // Normalize base into [0, mod-1]
            BigInteger b = @base % mod;
            if (b < 0) b += mod;

            if (exp.IsZero) return BigInteger.One % mod;

            // Если exp < 0, вычислим обратный элемент base^{-1} mod mod (если он существует)
            if (exp < 0)
            {
                var (g, x, y) = _extGcd.ExtendedGcd(b, mod);
                if (g != 1)
                    throw new ArgumentException("Modular inverse does not exist (base and mod not coprime), so negative exponent impossible.");
                BigInteger inv = x % mod;
                if (inv < 0) inv += mod;
                // base^{-1}
                b = inv;
                exp = BigInteger.Abs(exp);
            }

            // Экспоненцирование "square-and-multiply"
            BigInteger result = 1;
            BigInteger pow = b;
            BigInteger e = exp;

            while (e > 0)
            {
                if (!e.IsEven)
                    result = (result * pow) % mod;
                e >>= 1;
                if (e > 0)
                    pow = (pow * pow) % mod;
            }

            return result % mod;
        }
    }

    // --- Stateless service, который агрегирует компоненты ---
    public sealed class NumberTheoryService
    {
        public ILegendre Legendre { get; }
        public IJacobi Jacobi { get; }
        public IGcd Gcd { get; }
        public IExtendedGcd ExtendedGcd { get; }
        public IModExp ModExp { get; }

        // Конструктор создаёт и связывает компоненты — все компоненты stateless
        public NumberTheoryService()
        {
            // Связываем зависимости: ModExp требует ExtendedGcd для обратных элементов
            ExtendedGcd = new ExtendedGcdComponent();
            ModExp = new ModExpComponent(ExtendedGcd);
            Legendre = new LegendreComponent(ModExp);
            Jacobi = new JacobiComponent();
            Gcd = new GcdComponent();
        }
    }

    // --- Демонстрация использования ---
    // class Program
    // {
    //     static void Main()
    //     {
    //         var svc = new NumberTheoryService();

    //         Console.OutputEncoding = Encoding.UTF8;
    //         Console.WriteLine("=== Демонстрация stateless NumberTheoryService ===\n");

    //         // 1) НОД (Евклид)
    //         BigInteger a = 1989, b = 867;
    //         Console.WriteLine($"GCD({a}, {b}) = {svc.Gcd.Gcd(a, b)}");

    //         // 2) Расширённый Евклид (Безу)
    //         var (g, x, y) = svc.ExtendedGcd.ExtendedGcd(a, b);
    //         Console.WriteLine($"ExtendedGcd({a},{b}) -> g={g}, x={x}, y={y}  (проверка: a*x + b*y = {a * x + b * y})");

    //         // 3) Модульное возведение в степень (положительный экспонент)
    //         BigInteger @base = 7;
    //         BigInteger exp = 128;
    //         BigInteger mod = 1009;
    //         BigInteger mpow = svc.ModExp.ModPow(@base, exp, mod);
    //         Console.WriteLine($"{@base}^{exp} mod {mod} = {mpow}");

    //         // 4) Модульное возведение в степень (отрицательный экспонент) - требует обратного
    //         BigInteger base2 = 17;
    //         BigInteger expNeg = -1;
    //         BigInteger mod2 = 43;
    //         BigInteger powInv = svc.ModExp.ModPow(base2, expNeg, mod2);
    //         Console.WriteLine($"{base2}^{expNeg} mod {mod2} = {powInv}  (т.е. обратный элемент) проверка: (x*base) % mod = {(powInv * base2) % mod2}");

    //         // 5) Символ Лежандра (a|p), p простое (пример)
    //         BigInteger la = 10;
    //         BigInteger p = 13; // простое
    //         int leg = svc.Legendre.LegendreSymbol(la, p);
    //         Console.WriteLine($"Legendre({la},{p}) = {leg}  (проверка: {la}^{(p - 1) / 2} mod {p} = {svc.ModExp.ModPow(la, (p - 1) / 2, p)})");

    //         // 6) Символ Якоби (a|n), n нечётное (может быть составным)
    //         BigInteger ja = 1001;
    //         BigInteger n = 9907; // нечётное (пример)
    //         int jac = svc.Jacobi.JacobiSymbol(ja, n);
    //         Console.WriteLine($"Jacobi({ja},{n}) = {jac}");

    //         // Доп. тест: Jacobi когда n составное (пример)
    //         BigInteger ja2 = 5;
    //         BigInteger n2 = 21; // 21 = 3*7
    //         int jac2 = svc.Jacobi.JacobiSymbol(ja2, n2);
    //         Console.WriteLine($"Jacobi({ja2},{n2}) = {jac2}    (заметьте: если jacobi = 1, то a возможно квадратичный вычет по модулю n, но не гарантирован)");

    //         Console.WriteLine("\n=== Конец демонстрации ===");
    //     }
    // }
}
