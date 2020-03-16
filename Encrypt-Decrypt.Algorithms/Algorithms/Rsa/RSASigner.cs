using Encrypt_Decrypt.Algorithms.Algorithms.RSA.Extensions;
using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Rsa
{
    public class RSASigner
    {

        public static string RSASign(string conent, string privateKey)
        {
            return RSASign(conent, privateKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, Encoding.UTF8);
        }

        /// <summary>
        /// RSA Sign
        /// </summary>
        /// <param name="content">raw content </param>
        /// <param name="privateKey">private key</param>
        /// <param name="hashAlgorithmName">hashAlgorithm name</param>
        /// <param name="rSASignaturePadding">ras siginature padding</param>
        /// <param name="encoding">text encoding</param>
        /// <returns></returns>
        public static string RSASign(string content, string privateKey, HashAlgorithmName hashAlgorithmName, RSASignaturePadding rSASignaturePadding, Encoding encoding)
        {
            Check.Argument.IsNotEmpty(content, nameof(content));
            Check.Argument.IsNotEmpty(privateKey, nameof(privateKey));
            Check.Argument.IsNotNull(rSASignaturePadding, nameof(rSASignaturePadding));

            byte[] dataBytes = encoding.GetBytes(content);

            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.FromJsonString(privateKey);
                var signBytes = rsa.SignData(dataBytes, hashAlgorithmName, rSASignaturePadding);

                return Convert.ToBase64String(signBytes);
            }
        }

    }
}
