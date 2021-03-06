﻿using Encrypt_Decrypt.Algorithms.Algorithms.RSA.Extensions;
using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Keys
{
    class RsaKey
    {
        public static RSAKey CreateRsaKey(RsaSize rsaSize = RsaSize.R2048)
        {
             
            using (System.Security.Cryptography.RSA rsa = System.Security.Cryptography.RSA.Create())
            {
                rsa.KeySize = (int)rsaSize;
                 




                string publicKey = rsa.ToJsonString(false);
                string privateKey = rsa.ToJsonString(true);

                return new RSAKey()
                {
                    PublicKey = publicKey,
                    PrivateKey = privateKey,
                    Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                    Modulus = rsa.ExportParameters(false).Modulus.ToHexString()
                };
            }
        }

      
        public static RSAKey CreateRsaKey(System.Security.Cryptography.RSA rsa)
        {
            Check.Argument.IsNotNull(rsa, nameof(rsa));

            string publicKey = rsa.ToJsonString(false);
            string privateKey = rsa.ToJsonString(true);

            return new RSAKey()
            {
                PublicKey = publicKey,
                PrivateKey = privateKey,
                Exponent = rsa.ExportParameters(false).Exponent.ToHexString(),
                Modulus = rsa.ExportParameters(false).Modulus.ToHexString()
            };
        }
    }

    public class RSAKey
    {
        /// <summary>
        /// Rsa public key
        /// </summary>
        public string PublicKey { get; set; }

        /// <summary>
        /// Rsa private key
        /// </summary>
        public string PrivateKey { get; set; }

        /// <summary>
        /// Rsa public key Exponent
        /// </summary>
        public string Exponent { get; set; }

        /// <summary>
        /// Rsa public key Modulus
        /// </summary>
        public string Modulus { get; set; }
    }
}
