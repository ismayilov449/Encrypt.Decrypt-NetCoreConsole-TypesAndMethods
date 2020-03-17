# Encrypt.Decrypt-NetCoreConsole-TypesAndMethods
```•AES
  •Create AES Key 
    •AES encrypt
      •AES encrypt without iv (ECB mode)
      •AES encrypt with iv (CBC mode)
      •AES encrypt bytes with iv (CBC mode)
    •ASE decrypt
      •AES decrypt without iv (ECB mode)
      •AES decrypt with iv (CBC mode)
      •AES decrypt bytes with iv (CBC mode)

•DES
  •Create DES Key
  •Create DES Iv
    •DES encrypt
      •DES encrypt (ECB mode)
      •DES encrypt bytes (ECB mode)
      •DES encrypt bytes with iv (CBC mode)
    •DES decrypt
      •DES decrypt (ECB mode)
      •DES decrypt bytes (ECB mode)
      •DES decrypt bytes with iv (CBC mode)
 
•RSA
•Enum RsaSize
public enum RsaSize
{
    R2048=2048,
    R3072=3072,
    R4096=4096
};```
    •Create RSA Key with RsaSize
    •Rsa Sign and Verify method  
    •RSA encrypt
    •RSA decrypt
    •RSA from string
    •RSA with PEM  
 
//PKCS1
var pkcs1KeyTuple = EncryptProvider.RSAToPem(false);
var publicPem = pkcs1KeyTuple.publicPem;
var privatePem = pkcs1KeyTuple.privatePem;

//PKCS8
var pkcs8KeyTuple = EncryptProvider.RSAToPem(true);
publicPem = pkcs8KeyTuple.publicPem;
privatePem = pkcs8KeyTuple.privatePem;

//Rsa from pem key

var rsa = EncryptProvider.RSAFromPem(pemPublicKey);
rsa = EncryptProvider.RSAFromPem(pemPrivateKey);

//Rsa encrypt and decrypt with pem key

var rawStr = "xxx";
var enctypedStr = EncryptProvider.RSAEncryptWithPem(pemPublicKey, rawStr);
var decryptedStr = EncryptProvider.RSADecryptWithPem(pemPrivateKey, enctypedStr);


•MD5 
•HMAC-MD5

•SHA
  •SHA1
  •SHA256
  •SHA384
  •SHA512

•HMAC
  •HMAC-SHA1
  •HMAC-SHA256
  •HMAC-SHA384
  •HMAC-SHA512
