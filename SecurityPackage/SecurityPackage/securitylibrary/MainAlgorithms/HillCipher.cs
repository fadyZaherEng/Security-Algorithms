using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public static int siz;
        public static int b;
        public static bool f = true;
        public static int[,] newKeyInv;
        public static int[,] newPlainInv;
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            bool right = false;
            List<int> key2by2 = new List<int>();

            for (int i = 0; i <= 25; i++)
            {
                if (!f) break;
                for (int k = 0; k <= 25; k++)
                {
                    for (int l = 0; l <= 25; l++)
                    {
                        for (int m = 0; m <= 25; m++)
                        {
                            key2by2.Add(i); key2by2.Add(k); key2by2.Add(l); key2by2.Add(m);
                            List<int> cipherCheck = new List<int>();
                            int[,] KeyMatrix = new int[2, 2];
                            int c = 0;
                            for (int g = 0; g < siz; g++)
                            {
                                for (int j = 0; j < siz; j++)
                                {
                                    KeyMatrix[g, j] = key2by2.ElementAt(c);
                                    c++;
                                }
                            }
                            c = 0;
                            int plainCol = plainText.Count / siz;
                            int[,] PlainMatrix = new int[siz, plainCol];
                            int col = 0;
                            for (int h = 0; h < plainText.Count;)
                            {

                                for (int j = 0; j < siz; j++)
                                {
                                    PlainMatrix[j, col] = plainText.ElementAt(h);
                                    h++;
                                }
                                col++;
                            }
                            int[,] Multiply = new int[siz, plainCol];
                            for (int h = 0; h < siz; h++)
                            {
                                for (int j = 0; j < plainCol; j++)
                                {
                                    Multiply[h, j] = 0;
                                    for (int v = 0; v < siz; v++)
                                    {
                                        Multiply[h, j] += KeyMatrix[h, v] * PlainMatrix[v, j];
                                    }
                                }
                            }
                            for (int x = 0; x < plainCol; x++)
                            {
                                for (int j = 0; j < siz; j++)
                                {
                                    cipherCheck.Add(Multiply[j, x] % 26);
                                }
                            }
                            bool flag = false;
                            for (int b = 0; b < cipherText.Count; b++)
                            {
                                if (cipherText[b] != cipherCheck[b]) flag = true;
                            }
                            if (!flag)
                            {
                                right = true;
                                f = false;
                                break;
                            }
                            key2by2.Clear();
                        }
                    }
                }
            }
            if (right)
            {
                return key2by2;
               
            }
            else
            {
                throw new InvalidAnlysisException();
            }
        }

        public static int[,] MatInv2by2(int[,] matrix)
        {
            int det = matrix[0, 0] * matrix[1, 1] - matrix[0, 1] * matrix[1, 0];
            if (det != 1)
            {
                if (det != -1)
                    throw new Exception();
            }
            int[,] newMatrix = new int[2, 2];
            newMatrix[0, 0] = (matrix[1, 1] * det) % 26;
            newMatrix[1, 1] = (matrix[0, 0] * det) % 26;
            newMatrix[0, 1] = (-matrix[0, 1] * det) % 26;
            newMatrix[1, 0] = (-matrix[1, 0] * det) % 26;
            int[,] TransposeMatrix = new int[2, 2];
            TransposeMatrix[0, 0] = newMatrix[0, 0];
            TransposeMatrix[1, 0] = newMatrix[1, 0];
            TransposeMatrix[0, 1] = newMatrix[0, 1];
            TransposeMatrix[1, 1] = newMatrix[1, 1];
            return TransposeMatrix;
        }
        public static int[,] MatInv3by3(int[,] Matrix3)
        {
            int det = +Matrix3[0, 0] * (Matrix3[1, 1] * Matrix3[2, 2] - Matrix3[2, 1] * Matrix3[1, 2])
                      - Matrix3[0, 1] * (Matrix3[1, 0] * Matrix3[2, 2] - Matrix3[1, 2] * Matrix3[2, 0])
                      + Matrix3[0, 2] * (Matrix3[1, 0] * Matrix3[2, 1] - Matrix3[1, 1] * Matrix3[2, 0]);
            for (; det < 0;) det = det + 26;
            for (int i = 1; i < 26; i++)
            {
                if (((i * det) % 26) == 1)
                {
                    b = i;
                    break;
                }
            }

            int[,] result = new int[3, 3];
            result[0, 0] = ((Matrix3[1, 1] * Matrix3[2, 2] - Matrix3[2, 1] * Matrix3[1, 2]) * b) % 26;
            result[1, 0] = (-(Matrix3[0, 1] * Matrix3[2, 2] - Matrix3[0, 2] * Matrix3[2, 1]) * b) % 26;
            result[2, 0] = ((Matrix3[0, 1] * Matrix3[1, 2] - Matrix3[0, 2] * Matrix3[1, 1]) * b) % 26;
            result[0, 1] = (-(Matrix3[1, 0] * Matrix3[2, 2] - Matrix3[1, 2] * Matrix3[2, 0]) * b) % 26;
            result[1, 1] = ((Matrix3[0, 0] * Matrix3[2, 2] - Matrix3[0, 2] * Matrix3[2, 0]) * b) % 26;
            result[2, 1] = (-(Matrix3[0, 0] * Matrix3[1, 2] - Matrix3[1, 0] * Matrix3[0, 2]) * b) % 26;
            result[0, 2] = ((Matrix3[1, 0] * Matrix3[2, 1] - Matrix3[2, 0] * Matrix3[1, 1]) * b) % 26;
            result[1, 2] = (-(Matrix3[0, 0] * Matrix3[2, 1] - Matrix3[2, 0] * Matrix3[0, 1]) * b) % 26;
            result[2, 2] = ((Matrix3[0, 0] * Matrix3[1, 1] - Matrix3[1, 0] * Matrix3[0, 1]) * b) % 26;
            int[,] transposMatrixRes = new int[3, 3];
            for (int i = 0; i < 3; i++)
                for (int j = 0; j < 3; j++)
                    transposMatrixRes[i, j] = result[j, i];

            return transposMatrixRes;
        }
        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            if (key.Count == 4) siz = 2;
            if (key.Count == 9) siz = 3;
            int[,] KeyMatrix = new int[siz, siz];
            int c = 0;
            for (int i = 0; i < siz; i++)
            {
                for (int j = 0; j < siz; j++)
                {
                    KeyMatrix[i, j] = key.ElementAt(c);
                    c++;
                }
            }

            if (key.Count == 4) newKeyInv = MatInv2by2(KeyMatrix);

            if (key.Count == 9) newKeyInv = MatInv3by3(KeyMatrix);


            c = 0;
            int CipherCol = cipherText.Count / siz;

            for (int i = 0; i < siz; i++)
            {
                for (int j = 0; j < siz; j++)
                {
                    for (; newKeyInv[i, j] < 0;)
                        newKeyInv[i, j] = newKeyInv[i, j] + 26;
                }
            }


            int[,] CipherMatrix = new int[siz, CipherCol];
            int col = 0;
            for (int i = 0; i < cipherText.Count;)
            {

                for (int j = 0; j < siz; j++)
                {
                    CipherMatrix[j, col] = cipherText.ElementAt(i);
                    i++;
                }
                col++;
            }
            int[,] Multiply = new int[siz, CipherCol];
            for (int i = 0; i < siz; i++)
            {
                for (int j = 0; j < CipherCol; j++)
                {
                    Multiply[i, j] = 0;
                    for (int k = 0; k < siz; k++)
                    {
                        Multiply[i, j] += newKeyInv[i, k] * CipherMatrix[k, j];
                    }
                }
            }
            List<int> plain1 = new List<int>();
            for (int i = 0; i < CipherCol; i++)
            {
                for (int j = 0; j < siz; j++)
                {
                    plain1.Add((Multiply[j, i] % 26));
                }
            }
            return plain1;
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            List<int> cipher = new List<int>();
            if (key.Count == 4) siz = 2;
            if (key.Count == 9) siz = 3;
            int[,] KeyMatrix = new int[siz, siz];
            int c = 0;
            for (int i = 0; i < siz; i++)
            {
                for (int j = 0; j < siz; j++)
                {
                    KeyMatrix[i, j] = key.ElementAt(c);
                    c++;
                }
            }
            c = 0;
            int plainCol = plainText.Count / siz;
            int[,] PlainMatrix = new int[siz, plainCol];
            int col = 0;
            for (int i = 0; i < plainText.Count;)
            {

                for (int j = 0; j < siz; j++)
                {
                    PlainMatrix[j, col] = plainText.ElementAt(i);
                    i++;
                }
                col++;
            }
            int[,] Multiply = new int[siz, plainCol];
            for (int i = 0; i < siz; i++)
            {
                for (int j = 0; j < plainCol; j++)
                {
                    Multiply[i, j] = 0;
                    for (int k = 0; k < siz; k++)
                    {
                        Multiply[i, j] += KeyMatrix[i, k] * PlainMatrix[k, j];
                    }
                }
            }
            for (int i = 0; i < plainCol; i++)
            {
                for (int j = 0; j < siz; j++)
                {
                    cipher.Add(Multiply[j, i] % 26);
                }
            }
            return cipher;
        }


        public List<int> Analyse3By3Key(List<int> plainText, List<int> cipherText)
            
        {
            List<int> cipher4 = cipherText;
            List<int> plain4 = plainText;
            List<int> key = new List<int>();

            int[,] PlainMatrix = new int[3, 3];
            int c = 0;
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    PlainMatrix[i, j] = plain4.ElementAt(c);
                    c++;
                }
            }
            newPlainInv = MatInv3by3(PlainMatrix);
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    for (; newPlainInv[i, j] < 0;)
                        newPlainInv[i, j] = newPlainInv[i, j] + 26;
                }
            }

            int[,] CipherMatrix = new int[3, 3];
            int col = 0;
            for (int i = 0; i < cipher4.Count;)
            {

                for (int j = 0; j < 3; j++)
                {
                    CipherMatrix[j, col] = cipher4.ElementAt(i);
                    i++;
                }
                col++;
            }

            int[,] transposMatrixRes = new int[3, 3];
            for (int i = 0; i < 3; i++)
                for (int j = 0; j < 3; j++)
                    transposMatrixRes[i, j] = CipherMatrix[j, i];

            int[,] Multiply = new int[3, cipher4.Count / 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < cipher4.Count / 3; j++)
                {
                    Multiply[i, j] = 0;
                    for (int k = 0; k < 3; k++)
                    {
                        Multiply[i, j] += newPlainInv[i, k] * transposMatrixRes[k, j];
                    }
                }
            }

            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    key.Add((Multiply[j, i] % 26));
                }
            }
            return key;
        }

    }
}
