using Encrypt_Decrypt.Algorithms.Algorithms.RSA.Extensions;
using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Rsa.Extensions
{
    public class RSAFromString
    {
        public static System.Security.Cryptography.RSA RsaFromString(string rsaKey)
        {
            Check.Argument.IsNotEmpty(rsaKey, nameof(rsaKey));
            System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create();

            rsa.FromJsonString(rsaKey);
            return rsa;
        }
    }
}
