using System;
using System.Collections.Generic;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.RSA.Extensions
{
    internal class RSAParametersJson
    {
        //Public key Modulus
        public string Modulus { get; set; }
        //Public key Exponent
        public string Exponent { get; set; }

        public string P { get; set; }

        public string Q { get; set; }

        public string DP { get; set; }

        public string DQ { get; set; }

        public string InverseQ { get; set; }

        public string D { get; set; }
    }
}
