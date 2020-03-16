using Encrypt_Decrypt.Algorithms.Algorithms.Keys;
using Encrypt_Decrypt.Algorithms.Algorithms.RSA.Extensions;
using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Rsa.Extensions
{
    public class RSAPam
    {
        public static (string publicPem, string privatePem) RSAToPem(bool isPKCS8)
        {
            var rsaKey = RsaKey.CreateRsaKey();

            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.FromJsonString(rsaKey.PrivateKey);

                var publicPem = RsaProvider.ToPem(rsa, false, isPKCS8);
                var privatePem = RsaProvider.ToPem(rsa, true, isPKCS8);

                return (publicPem, privatePem);
            }
        }

        /// <summary>
        /// RSA From pem
        /// </summary>
        /// <param name="pem"></param>
        /// <returns></returns>
        public static System.Security.Cryptography.RSA RSAFromPem(string pem)
        {
            Check.Argument.IsNotEmpty(pem, nameof(pem));
            return RsaProvider.FromPem(pem);
        }

    }
}
