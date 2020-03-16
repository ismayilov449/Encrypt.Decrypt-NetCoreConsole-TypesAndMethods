using System;
using System.Collections.Generic;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Shared
{
    internal static class ArrayExtensions
    {
      
        internal static T[] Sub<T>(this T[] arr, int start, int count)
        {
            T[] val = new T[count];
            for (var i = 0; i < count; i++)
            {
                val[i] = arr[start + i];
            }
            return val;
        }
    }
}
