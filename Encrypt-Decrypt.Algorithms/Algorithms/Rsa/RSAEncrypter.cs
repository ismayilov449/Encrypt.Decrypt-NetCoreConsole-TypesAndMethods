using Encrypt_Decrypt.Algorithms.Algorithms.Rsa.Extensions;
using Encrypt_Decrypt.Algorithms.Algorithms.RSA.Extensions;
using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Rsa
{
    public class RSAEncrypter
    {

        public static string RSAEncrypt(string publicKey, string srcString)
        {
            string encryptStr = RSAEncrypt(publicKey, srcString, RSAEncryptionPadding.OaepSHA512);
            return encryptStr;
        }


        public static string RSAEncrypt(string publicKey, string srcString, RSAEncryptionPadding padding)
        {
            Check.Argument.IsNotEmpty(publicKey, nameof(publicKey));
            Check.Argument.IsNotEmpty(srcString, nameof(srcString));
            Check.Argument.IsNotNull(padding, nameof(padding));

            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.FromJsonString(publicKey);
                var maxLength = GetMaxRsaEncryptLengthClass.GetMaxRsaEncryptLength(rsa, padding);
                var rawBytes = Encoding.UTF8.GetBytes(srcString);

                if (rawBytes.Length > maxLength)
                {
                    throw new OutofMaxlengthException($"'{srcString}' is out of max encrypt length {maxLength}", maxLength, rsa.KeySize, padding);
                }

                byte[] encryptBytes = rsa.Encrypt(rawBytes, padding);
                return encryptBytes.ToHexString();
            }
        }
         
    }
}
