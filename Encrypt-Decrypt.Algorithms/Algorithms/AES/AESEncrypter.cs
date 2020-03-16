using Encrypt_Decrypt.Algorithms.Shared;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt_Decrypt.Algorithms.Algorithms.AES
{
    public class AESEncrypter
    {

        public static string AESEncrypt(string data, string key, string vector)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));

            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsNotOutOfRange(vector.Length, 16, 16, nameof(vector));

            byte[] plainBytes = Encoding.UTF8.GetBytes(data);

            var encryptBytes = AESEncrypt(plainBytes, key, vector);
            if (encryptBytes == null)
            {
                return null;
            }
            return Convert.ToBase64String(encryptBytes);
        }

        public static byte[] AESEncrypt(byte[] data, string key, string vector)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));

            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            Check.Argument.IsNotEmpty(vector, nameof(vector));
            Check.Argument.IsNotOutOfRange(vector.Length, 16, 16, nameof(vector));

            byte[] plainBytes = data;
            byte[] bKey = new byte[32];
            Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);
            byte[] bVector = new byte[16];
            Array.Copy(Encoding.UTF8.GetBytes(vector.PadRight(bVector.Length)), bVector, bVector.Length);

            byte[] encryptData = null; // encrypted data
            using (Aes Aes = Aes.Create())
            {
                try
                {
                    using (MemoryStream Memory = new MemoryStream())
                    {
                        using (CryptoStream Encryptor = new CryptoStream(Memory,
                         Aes.CreateEncryptor(bKey, bVector),
                         CryptoStreamMode.Write))
                        {
                            Encryptor.Write(plainBytes, 0, plainBytes.Length);
                            Encryptor.FlushFinalBlock();

                            encryptData = Memory.ToArray();
                        }
                    }
                }
                catch
                {
                    encryptData = null;
                }
                return encryptData;
            }
        }

        public static string AESEncrypt(string data, string key)
        {
            Check.Argument.IsNotEmpty(data, nameof(data));
            Check.Argument.IsNotEmpty(key, nameof(key));
            Check.Argument.IsNotOutOfRange(key.Length, 32, 32, nameof(key));

            using (MemoryStream Memory = new MemoryStream())
            {
                using (Aes aes = Aes.Create())
                {
                    byte[] plainBytes = Encoding.UTF8.GetBytes(data);
                    byte[] bKey = new byte[32];
                    Array.Copy(Encoding.UTF8.GetBytes(key.PadRight(bKey.Length)), bKey, bKey.Length);

                    aes.Mode = CipherMode.ECB;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.KeySize = 128;
                    aes.Key = bKey;

                    using (CryptoStream cryptoStream = new CryptoStream(Memory, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        try
                        {
                            cryptoStream.Write(plainBytes, 0, plainBytes.Length);
                            cryptoStream.FlushFinalBlock();
                            return Convert.ToBase64String(Memory.ToArray());
                        }
                        catch (Exception ex)
                        {
                            return null;
                        }
                    }
                }
            }
        }
    }
}
