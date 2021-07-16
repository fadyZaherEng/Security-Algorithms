using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        Dictionary<Char, int> EncrptMapSmall = new Dictionary<Char, int>();
        Dictionary<int, Char> DecrptMapSmall = new Dictionary<int, Char>();
        Dictionary<Char, int> EncrptMapCapital = new Dictionary<Char, int>();
        Dictionary<int, Char> DecrptMapCapital = new Dictionary<int, Char>();

        public Ceaser()
        {
            Char s = 'a';
            char c = 'A';
            for (int i = 0; i < 26; i++)
            {
                EncrptMapSmall[s] = i;
                DecrptMapSmall[i] = s;
                EncrptMapCapital[c] = i;
                DecrptMapCapital[i] = c;
                c++; s++;
            }
        }
        public string Encrypt(string plainText, int key)
        {

            String CipherText = "";
            foreach (Char ch in plainText)
            {
                if (Char.IsUpper(ch))
                {
                    int res = (EncrptMapCapital[ch] + key) % 26;
                    CipherText += DecrptMapCapital[res];
                }
                else
                {
                    int res = (EncrptMapSmall[ch] + key) % 26;
                    CipherText += DecrptMapSmall[res];
                }

            }
            return CipherText;
        }

        public string Decrypt(string cipherText, int key)
        {

            String PlanText = "";
            foreach (Char ch in cipherText)
            {
                if (Char.IsUpper(ch))
                {
                    int res = (EncrptMapCapital[ch] - key) % 26;
                    if (res < 0) res += 26;
                    PlanText += DecrptMapCapital[res];
                }
                else
                {
                    int res = (EncrptMapSmall[ch] - key) % 26;
                    if (res < 0) res += 26;
                    PlanText += DecrptMapSmall[res];
                }

            }
            return PlanText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            Char First_Char_Plain = plainText[0];
            Char First_Char_Cipher = cipherText.ToLower()[0];
            int Ret_key;
            if (Char.IsUpper(First_Char_Plain) && Char.IsUpper(First_Char_Cipher))
            {
                Ret_key = EncrptMapCapital[First_Char_Cipher]-EncrptMapCapital[First_Char_Plain];
            }
            else
            {
                Ret_key =EncrptMapSmall[First_Char_Cipher]-EncrptMapSmall[First_Char_Plain];
            }
            if (Ret_key < 0) Ret_key += 26;
            return Ret_key;
        }
    }
}
