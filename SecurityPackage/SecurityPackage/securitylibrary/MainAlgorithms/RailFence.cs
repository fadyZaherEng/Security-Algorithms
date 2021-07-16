using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 2;
            while (true)
            {
                String[] arr = new string[key];
                int len = cipherText.Length / key;
                int z = (cipherText.Length - key * len);
                int i = 0;
                for (int k = 0; k < key; k++)
                {
                    for (int j = 0; j < len; j++)
                    {
                        arr[k] += cipherText.ToLower()[i];
                        i++;
                        if (j == len - 1 && z > 0)
                        {
                            arr[k] += cipherText.ToLower()[i];
                            i++;
                            z--;
                        }
                    }
                }
                i = 0;
                String plain = "";

                for (int h = 0; h < len; h++)
                {
                    for (int j = 0; j < key; j++)
                    {
                        plain += arr[j][h];
                    }
                }

                if (plainText.Contains(plain))
                {
                    break;
                }
                key++;
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            String[] arr = new string[key];
            int len = cipherText.Length / key;
            int z = (cipherText.Length - key * len);
            int i = 0;
            for (int k = 0; k < key; k++)
            {
                for (int j = 0; j < len; j++)
                {
                    arr[k] += cipherText.ToLower()[i];
                    i++;
                    if (j == len - 1 && z > 0)
                    {
                        arr[k] += cipherText.ToLower()[i];
                        i++;
                        z--;
                    }
                }
            }
            i = 0;
            String plainText = "";

            for (int h = 0; h < len; h++)
            {
                for (int j = 0; j < key; j++)
                {
                    plainText += arr[j][h];
                }
            }
            for (int j = 0; j < key; j++)
            {
                int c = arr[j].Length;
                if (len + 1 == arr[j].Length)
                {
                    plainText += arr[j][len];
                }

            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            String[] arr = new string[key];
            for (int i = 0; i < plainText.Length;)
            {
                for (int j = 0; j < key; j++)
                {
                    if (i == plainText.Length)
                    {
                        break;
                    }
                    Char c = plainText[i];
                    arr[j] += plainText[i];
                    i++;
                }
            }
            String Cipher = "";
            foreach (String c in arr)
            {
                Cipher += c;
            }
            return Cipher;
        }
    }
}
