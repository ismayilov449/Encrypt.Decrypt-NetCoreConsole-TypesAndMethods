using Encrypt_Decrypt.Algorithms.Algorithms.RSA.Extensions;
using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Rsa
{
    public class RSADecrypter
    {
        public static string RSADecrypt(string privateKey, string srcString)
        {
            string decryptStr = RSADecrypt(privateKey, srcString, RSAEncryptionPadding.OaepSHA512);
            return decryptStr;
        }

        public static string RSADecryptWithPem(string privateKey, string srcString)
        {
            string decryptStr = RSADecrypt(privateKey, srcString, RSAEncryptionPadding.Pkcs1, true);
            return decryptStr;
        }

        public static string RSADecrypt(string privateKey, string srcString, RSAEncryptionPadding padding, bool isPemKey = false)
        {
            Check.Argument.IsNotEmpty(privateKey, nameof(privateKey));
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotNull(padding, nameof(padding));

            System.Security.Cryptography.RSA rsa;
            if (isPemKey)
            {
                rsa = RsaProvider.FromPem(privateKey);
            }
            else
            {
                rsa = System.Security.Cryptography.RSA.Create();
                rsa.FromJsonString(privateKey);
            }

            using (rsa)
            {
                byte[] srcBytes = srcString.ToBytes();
                byte[] decryptBytes = rsa.Decrypt(srcBytes, padding);
                return Encoding.UTF8.GetString(decryptBytes);
            }
        }
    }
}
