using Encrypt_Decrypt.Algorithms.Algorithms.Keys;
using Encrypt_Decrypt.Algorithms.Algorithms.Rsa;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Encrypt_Decrypt.Algorithms
{
    class Program
    {
        static void Main(string[] args)
        {

            Console.WriteLine("** RSA **");
            var rsaKey = RsaKey.CreateRsaKey();
            var plaintext = "Hello world 123456789/*-+!@#$%^&*()-=_+";
            var publicKey = rsaKey.PublicKey;
            var privateKey = rsaKey.PrivateKey;
            //var exponent = rsaKey.Exponent;
            //var modulus = rsaKey.Modulus;

         
            
           var encrypted = RSAEncrypter.RSAEncrypt(publicKey, plaintext, RSAEncryptionPadding.OaepSHA512);
           var decrypted = RSADecrypter.RSADecrypt(privateKey, encrypted, RSAEncryptionPadding.OaepSHA512);


            Console.WriteLine("Encrypted: " + encrypted);
            Console.WriteLine("Decrypted: " + decrypted);
            //Console.WriteLine("publicKey: {0} privateKey: {1}", publicKey, privateKey);

        

            Console.ReadKey();

        }
    }
}
