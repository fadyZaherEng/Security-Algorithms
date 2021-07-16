using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        Dictionary<Char, Char> Alphabet_c = new Dictionary<Char, Char>();
        Dictionary<Char, Char> Alphabet_s = new Dictionary<Char, Char>();
        public Monoalphabetic()
        {
            char s = 'a';
            char c = 'A';
            for (int i = 0; i < 26; i++)
            {
                Alphabet_c[c] = c;
                Alphabet_s[s] = s;
                s++; c++;
            }
        }
        public string Analyse(string plainText, string cipherText)
        {
            Dictionary<Char, Char> key = new Dictionary<char, char>();
            //intial all character with dot value
            Char Alphabatic_Counter = 'a';
            for (int i = 0; i < 26; i++)
            {
                key.Add(Alphabatic_Counter, '.');
                Alphabatic_Counter++;
            }
            //store Latters
            String latters = "abcdefghijklmnopqrstuvwxyz";
            int j = 0;
            //store key value 
            foreach (Char c in plainText.ToLower())
            {
                key[c] = cipherText.ToLower()[j];
                j++;
            }
            //complete rest of char that untill value it is dot(.) with rest of Latters
            foreach (Char c in latters)
            {
                if (!key.ContainsValue(c))
                {
                    foreach (var kvp in key)
                    {
                        if (kvp.Value == '.')
                        {
                            key[kvp.Key] = c;
                            break;
                        }
                    }

                }
            }
            //store in String to Return
            String RetKey = "";
            foreach (var kvp in key)
            {
                RetKey += kvp.Value;
            }
            return RetKey;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            foreach (Char ch in cipherText.ToLower())
            {
                if (Char.IsLower(ch))
                {
                    char start = 'a';
                    for (int q = 0; q < 26; q++)
                    {
                        if (ch.Equals(key[q]))
                        {
                            plainText += Alphabet_s[start];
                        }
                        start++;
                    }
                }
                if (Char.IsUpper(ch))
                {
                    char start = 'A';
                    for (int q = 0; q < 26; q++)
                    {
                        if (ch.Equals(key[q]))
                        {
                            plainText += Alphabet_c[start];
                        }
                        start++;
                    }
                }
            }
            return plainText;

        }

        public string Encrypt(string plainText, string key)
        {
            string CipherText = "";
            foreach (Char ch in plainText)
            {
                if (Char.IsUpper(ch))
                {
                    char start = 'A';
                    for (int q = 0; q < 26; q++)
                    {
                        if (ch.Equals(Alphabet_c[start]))
                        {

                            CipherText += key[q];
                        }
                        start++;
                    }
                }
                if (Char.IsLower(ch))
                {
                    char start = 'a';
                    for (int w = 0; w < 26; w++)
                    {
                        if (ch.Equals(Alphabet_s[start]))
                        {

                            CipherText += key[w];
                        }
                        start++;
                    }
                }

            }
            return CipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54  
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            String Latters = "abcdefghijklmnopqrstuvwxyz";
            String Cipher = cipher.ToLower();
            Dictionary<Char, int> Latter_Frequency = new Dictionary<Char, int>();
            Dictionary<Char, Char> Ins = new Dictionary<Char, Char>();
            //intial frequnecy of Latters with zero
            foreach (Char c in Latters)
            {
                Latter_Frequency.Add(c, 0);
            }
            //calculate freq of Latters
            foreach (Char c in Cipher)
            {
                Latter_Frequency[c] += 1;
            }
            //swap Latters with key based on freq
            String Frq_info = "etaoinsrhldcumfpgwybvkxjqz";
            int i = 0;
            foreach (var item in Latter_Frequency.OrderByDescending(c => c.Value))
            {
                Ins.Add(item.Key, Frq_info[i]);
                i++;
            }
            //find value of plain text 
            String ret_Plain_text = "";
            foreach (Char c in Cipher)
            {
                ret_Plain_text += Ins[c];
            }
            return ret_Plain_text;
        }
    }
}
