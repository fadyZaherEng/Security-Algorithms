using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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
            String res = "";
            for (int i = 0; i < Key.Length; i++)
            {
                String str = "";
                for (int j = i; j < Key.Length; j++)
                {
                    str += Key[j];
                }
                if (plainText.ToLower().Contains(str))
                {
                    break;
                }
                else
                {
                    res += Key[i];
                }
            }
            return res;
        }

        public string Decrypt(string cipherText, string key)
        {
            String PlainText = "";

            for (int i = 0; i< cipherText.ToLower().Length; i++)
            {
                //get index of cipher
                int Result = (alphabet.IndexOf(cipherText.ToLower()[i]) - alphabet.IndexOf(key[i]) % 26);
                //chek negative
                if (Result < 0) Result += 26;
                //complete key with rest of plain text
                key+= alphabet[Result];
                //set Plain text
                PlainText += alphabet[Result];
            }
            return PlainText;
        }

        public string Encrypt(string plainText, string key)
        {
          String Key = String.Concat(key, plainText).Substring(0, String.Concat(key, plainText).Length - key.Length);
          String cipherText = "";
          for (int j = 0; j < plainText.Length; j++)
           cipherText += alphabet[(alphabet.IndexOf(Key[j]) + alphabet.IndexOf(plainText[j]))%26]; 
          return cipherText;
        }
    }
}
