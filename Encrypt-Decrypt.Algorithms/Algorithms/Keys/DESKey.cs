using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.Keys
{
    public class DESKey
    {
        public static string CreateDesKey()
        {
            return RandomStringGenerator.GetRandomStr(24);
        }
 
        public static string CreateDesIv()
        {
            return RandomStringGenerator.GetRandomStr(8);
        }
    }
}
