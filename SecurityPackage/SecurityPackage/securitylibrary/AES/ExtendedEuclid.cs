using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int b = number, m = baseN;
            int A1 = 1, A2 = 0, A3 = m, B1 = 0, B2 = 1, B3 = b, Q;
            int Temp1, Temp2, Temp3;
            while (true)
            {
                if (B3 == 0)
                {
                    return -1;
                }
                if (B3 == 1)
                {
                    if (B2 < 0) B2 += 26;
                    return B2;
                }
                Q = A3 / B3;
                Temp1 = A1 - Q * B1; Temp2 = A2 - Q * B2; Temp3 = A3 - Q * B3;
                A1 = B1; A2 = B2; A3 = B3;
                B1 = Temp1; B2 = Temp2; B3 = Temp3;

            }
        }
    }
}
