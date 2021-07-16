using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public static int[] arr;
        public static List<List<int>> lists = new List<List<int>>();
        public List<int> Analyse(string plainText, string cipherText)
        {
            List<int> Key = new List<int>();
            List<int> temp = new List<int>();
            bool flag = true;
            String mainPlain1 = plainText;      
            int counter = 1;
            while (flag)
            {
                for (int j = 1; j <= counter; j++)
                {
                    temp.Add(j);
                }
                int[] arr1 = temp.ToArray();
                lists = CallPermutation(arr1);
                temp.Clear();

                foreach (List<int> key in lists)
                {
                    int row;
                    if (plainText.Length % key.Count == 0) row = plainText.Length / key.Count;
                    else
                    {
                        row = 1 + (plainText.Length / key.Count);
                    }
                    int col = key.Count;
                    int index = 0;
                    Char[,] arr = new char[row, col];
                    for (int i = 0; i < row; i++)
                    {
                        for (int j = 0; j < col; j++)
                        {
                            if (index < plainText.Length)
                            {
                                arr[i, j] = plainText[index];
                                index++;
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                    String cipher = "";
                    for (int i = 1; i <= col; i++)
                    {
                        int index1 = key.IndexOf(i);
                        for (int j = 0; j < row; j++)
                        {
                            if (arr[j, index1] != '\0')
                            {
                                cipher += arr[j, index1];
                            }
                        }
                    }
                    if (cipher.Equals(cipherText.ToLower()))
                    {
                        Key = key;
                        flag = false;
                        break;
                    }

                }
                counter++;
            }
            return Key;
        }
        static List<List<int>> CallPermutation(int[] ran)
        {
            var list = new List<List<int>>();
            return Permutation(ran, 0, ran.Length - 1, list);
        }

        static List<List<int>> Permutation(int[] ran, int s, int e, List<List<int>> list)
        {
            if (s == e)
            {
                list.Add(new List<int>(ran));
            }
            else
            {
                for (var i = s; i <= e; i++)
                {
                    SwapNum(ref ran[s], ref ran[i]);
                    Permutation(ran, s + 1, e, list);
                    SwapNum(ref ran[s], ref ran[i]);
                }
            }

            return list;
        }

        static void SwapNum(ref int a, ref int b)
        {
            var Temp = a;
            a = b;
            b = Temp;
        }
        public string Decrypt(string cipherText, List<int> key)
        {
            int row;
            if (cipherText.Length % key.Count == 0) row = cipherText.Length / key.Count;
            else
            {
                row = 1 + (cipherText.Length / key.Count);
            }
            int col = key.Count;
            int colFree = (row * col) - cipherText.Length;

            int index = 0, inx = 0;
            Char[,] arr = new char[row, col];
            int count = 1;
            for (int i = 0; i < col; i++)
            {
                inx = key.IndexOf(count);
                count++;
                for (int j = 0; j < row; j++)
                {
                    if (j != row - 1)
                    {
                        arr[j, inx] = cipherText[index];
                        index++;
                    }
                    else if ((j == row - 1) && !(((i + 1) + colFree) > col))
                    {
                        arr[j, inx] = cipherText[index];
                        index++;
                    }

                }
            }
            String plain = "";
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (arr[i, j] != '\0')
                    {
                        Char x = arr[i, j];
                        plain += arr[i, j];
                    }
                }
            }
            return plain;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            int row;
            if (plainText.Length % key.Count == 0) row = plainText.Length / key.Count;
            else
            {
                row = 1 + (plainText.Length / key.Count);
            }
            int col = key.Count;
            int index = 0;
            Char[,] arr = new char[row, col];
            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < col; j++)
                {
                    if (index < plainText.Length)
                    {
                        arr[i, j] = plainText[index];
                        index++;
                    }
                    else
                    {
                        break;
                    }
                }
            }
            String cipher = "";
            for (int i = 1; i <= col; i++)
            {
                int index1 = key.IndexOf(i);
                for (int j = 0; j < row; j++)
                {
                    if (arr[j, index1] != '\0')
                    {
                        cipher += arr[j, index1];
                    }
                }
            }
            return cipher;
        }
    }
}
