using Encrypt_Decrypt.Algorithms.Algorithms.RSA.Extensions;
using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Rsa
{
    public class RSAVerifier
    {
        public static bool RSAVerify(string content, string signStr, string publickKey)
        {
            return RSAVerify(content, signStr, publickKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, Encoding.UTF8);
        }

        /// <summary>
        /// RSA Verify
        /// </summary>
        /// <param name="content">raw content</param>
        /// <param name="signStr">sign str</param>
        /// <param name="publickKey">public key</param>
        /// <param name="hashAlgorithmName">hashAlgorithm name</param>
        /// <param name="rSASignaturePadding">ras siginature padding</param>
        /// <param name="encoding">text encoding</param>
        /// <returns></returns>
        public static bool RSAVerify(string content, string signStr, string publickKey, HashAlgorithmName hashAlgorithmName, RSASignaturePadding rSASignaturePadding, Encoding encoding)
        {
            Check.Argument.IsNotEmpty(content, nameof(content));
            Check.Argument.IsNotEmpty(signStr, nameof(signStr));

            byte[] dataBytes = encoding.GetBytes(content);
            byte[] signBytes = Convert.FromBase64String(signStr);

            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.FromJsonString(publickKey);
                return rsa.VerifyData(dataBytes, signBytes, hashAlgorithmName, rSASignaturePadding);
            }
        }
    }
}
