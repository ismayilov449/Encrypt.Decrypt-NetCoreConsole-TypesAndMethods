using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Keys
{
    public class AESKey
    {
        public string Key { get; set; }

        public string IV { get; set; }

        public static AESKey CreateAESKey()
        {
            return new AESKey()
            {
                Key = RandomStringGenerator.GetRandomStr(32),
                IV = RandomStringGenerator.GetRandomStr(16)
            };
        }

    }
}
