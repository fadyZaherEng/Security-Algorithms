using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public String alphabet = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            String Key = "";

            for (int j = 0; j < plainText.ToLower().Length; j++)

            {
                Char a = cipherText.ToLower()[j];
                Char b = plainText.ToLower()[j];
                int x = alphabet.IndexOf(a);
                int y = alphabet.IndexOf(b);
                if (x - y < 0)
                {
                    Key += alphabet[(x - y) + 26];
                }
                else
                {
                    Key += alphabet[x - y];
                }
            }

            String str = "";
            for (int i = 0; i < Key.Length; i++)
            {
                str += Key[i];
                if (str.Equals(Key.Substring(i + 1, str.Length))) break;
            }
            return str;
        }

        public string Decrypt(string cipherText, string key)
        {
            String Key = "";
            while (true)
            {
                if (Key.Length < cipherText.Length)
                {
                    Key = String.Concat(Key, key);
                }
                else
                {
                    break;
                }

            }
            String PlainText = "";

            for (int i = 0; i < cipherText.ToLower().Length; i++)
            {
                //get index of cipher
                int Result = (alphabet.IndexOf(cipherText.ToLower()[i]) - alphabet.IndexOf(Key[i]) % 26);
                //chek negative
                if (Result < 0) Result += 26;
                //set Plain text
                PlainText += alphabet[Result];
            }
            return PlainText;
        }

        public string Encrypt(string plainText, string key)
        {
            String Key="";
            while (true)
            {
                if (Key.Length < plainText.Length)
                {
                    Key = String.Concat(Key, key);
                }
                else
                {
                    break;
                }
              
            }
            String cipherText = "";
            for (int j = 0; j < plainText.Length; j++)
                cipherText += alphabet[(alphabet.IndexOf(Key[j]) + alphabet.IndexOf(plainText[j])) % 26];
            return  cipherText ;
        }
    }
}