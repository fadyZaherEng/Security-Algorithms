using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            int C1row = -1, C1col = -1, C2row = -1, C2col = -1;
            //work on Draw Matrix
            String[,] arr = Draw_Matrix(key);
            //work on algo
            string mainKey =key.ToLower();
            string mainCipher = cipherText.ToLower();
            String mainplain = "";
            int z = 0;
            for (; z < mainCipher.Length; z += 2)
            {
                for (int k = 0; k < 5; k++)
                {
                    for (int l = 0; l < 5; l++)
                    {
                        if (arr[k, l] == mainCipher[z] + "")
                        {
                            C1col = l; C1row = k;
                        }
                        if (arr[k, l] == mainCipher[z + 1] + "")
                        {
                            C2col = l; C2row = k;
                        }
                    }
                }
                if (C1row != C2row && C1col != C2col)
                {
                    mainplain += arr[C1row, C2col];
                    mainplain += arr[C2row, C1col];
                }
                else if (C1row == C2row)
                {
                    if (C1col == 0)
                    {
                        mainplain += arr[C1row, 4];
                    }
                    else
                    {
                        mainplain += arr[C1row, C1col - 1];
                    }
                    if (C2col == 0)
                    {
                        mainplain += arr[C2row, 4];
                    }
                    else
                    {
                        mainplain += arr[C2row, C2col - 1];
                    }
                }
                else if (C1col == C2col)
                {
                    if (C1row == 0)
                    {
                        mainplain += arr[4, C1col];
                    }
                    else
                    {
                        mainplain += arr[C1row - 1, C1col];
                    }
                    if (C2row == 0)
                    {
                        mainplain += arr[4, C2col];
                    }
                    else
                    {
                        mainplain += arr[C2row - 1, C2col];
                    }
                }

            }
            //delete x that i added it before return
            if (mainplain[mainplain.Length - 1] == 'x')
            {
                mainplain = mainplain.Remove(mainplain.Length - 1, 1);
            }
            for (int p = 0; p < mainplain.Length - 2; p++)
            {
                if (mainplain[p] == mainplain[p + 2] && mainplain[p + 1] == 'x')
                {
                    mainplain = mainplain.Remove(p + 1,1);
                }
                else
                {
                    p++;
                }
            }

            return mainplain;
        }
        public String[,] Draw_Matrix(String key)
        {
            HashSet<String> uniqueChar = new HashSet<String>();
            String[,] arr = new String[5, 5];
            // work on grad
            foreach (Char c in key)
            {
                uniqueChar.Add(c + "");
            }
            int i = 0, j = 0;
            foreach (String C in uniqueChar)
            {
                if (j == 5)
                {
                    j = 0;
                    i++;
                }
                if (C.Equals("i") || C.Equals("j"))
                {
                    arr[i, j] = "i";
                    j++;
                }
                else
                {
                    arr[i, j] = C;
                    j++;
                }
            }
            Char a = 'a';
            for (int k = 0; k < 5; k++)
            {
                for (int l = 0; l < 5; l++)
                {

                    if (arr[k, l] == null)
                    {
                        for (; a <= 'z'; a++)
                        {
                            if (a == 'j') continue;
                            if (a == 'i')
                            {
                                bool s = true;
                                for (int c = 0; c < 5; c++)
                                {
                                    for (int b = 0; b < 5; b++)
                                    {
                                        if ((arr[c, b] == "i")) s = false;
                                    }
                                }
                                if (s)
                                {
                                    arr[k, l] = "i";
                                    a++; a++;
                                    break;
                                }
                            }
                            else if (!uniqueChar.Contains(a + ""))
                            {
                                arr[k, l] = a + "";
                                a++;
                                break;
                            }
                        }

                    }
                }
            }
            return arr;
        }
        public string Encrypt(string plainText, string key)
        {
            int C1row = -1, C1col = -1, C2row = -1, C2col = -1;
            String mainCipher = "";
            //work on plainText
            for (int f = 0; f < plainText.Length; f += 2)
            {
                if (f == plainText.Length - 1)
                {
                    plainText += 'x';
                }
                else if (plainText[f] == plainText[f + 1])
                {
                    plainText = plainText.Substring(0, f + 1) + 'x' + plainText.Substring(f + 1);
                }
            }
            // work on draw matrix
            String[,] arr = Draw_Matrix(key);
            ////////////////////////////////////////////////////////////////////////
            //implement algo
            int h = 0;
            for (; h < plainText.Length; h += 2)
            {
                for (int k = 0; k < 5; k++)
                {
                    for (int l = 0; l < 5; l++)
                    {
                        if (arr[k, l] == plainText[h] + "")
                        {
                            C1col = l; C1row = k;
                        }
                        if (arr[k, l] == plainText[h + 1] + "")
                        {
                            C2col = l; C2row = k;
                        }
                    }
                }
                if (C1row != C2row && C1col != C2col)
                {
                    mainCipher += arr[C1row, C2col];
                    mainCipher += arr[C2row, C1col];
                }
                else if (C1row == C2row)
                {
                    if (C1col == 4)
                    {
                        mainCipher += arr[C1row, 0];
                    }
                    else
                    {
                        mainCipher += arr[C1row, C1col + 1];
                    }
                    if (C2col == 4)
                    {
                        mainCipher += arr[C2row, 0];
                    }
                    else
                    {
                        mainCipher += arr[C2row, C2col + 1];
                    }
                }
                else if (C1col == C2col)
                {
                    if (C1row == 4)
                    {
                        mainCipher += arr[0, C1col];
                    }
                    else
                    {
                        mainCipher += arr[C1row + 1, C1col];
                    }
                    if (C2row == 4)
                    {
                        mainCipher += arr[0, C2col];
                    }
                    else
                    {
                        mainCipher += arr[C2row + 1, C2col];
                    }
                }

            }
            return mainCipher;
        }
    }
}
