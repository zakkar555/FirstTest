using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;

namespace CryptoPassword
{
    class Secure
    {
        public static byte[] EncryptString(string dataStr, byte[] dataKey, byte[] dataIV)
        {
            if (dataStr == null || dataStr.Length <= 0)
                throw new ArgumentNullException("dataStr");
            if (dataKey == null || dataKey.Length <= 0)
                throw new ArgumentNullException("dataKey");
            if (dataIV == null || dataIV.Length <= 0)
                throw new ArgumentNullException("dataIV");

            byte[] encrypted;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = dataKey;
                aesAlg.IV = dataIV;

                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(dataStr);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }

            }
            return encrypted;
        }


        public static string DecryptString(byte[] dataStr, byte[] dataKey, byte[] dataIV)
        {
            if (dataStr == null || dataStr.Length <= 0)
                throw new ArgumentNullException("dataStr");
            if (dataKey == null || dataKey.Length <= 0)
                throw new ArgumentNullException("dataKey");
            if (dataIV == null || dataIV.Length <= 0)
                throw new ArgumentNullException("dataIV");

            string decrypted;
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = dataKey;
                aesAlg.IV = dataIV;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(dataStr))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            decrypted = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            return decrypted;
        }

    }


    class Program
    {
        static void Main(string[] args)
        {
            string original = "some text example";

            using (Aes aes = Aes.Create())
            {
                byte[] encrypted = Secure.EncryptString(original, aes.Key, aes.IV);

                var str = Secure.DecryptString(encrypted, aes.Key, aes.IV);
                Console.WriteLine(str);
                Console.ReadKey();
            }
        }
    }
}
