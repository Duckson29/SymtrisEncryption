using System.Security.Cryptography;
using System.IO;
using System;
using EncryptionLibrary.InterFaces;

namespace EncryptionLibrary
{
    internal class DESWrapper : IAesEncryption
    {
        private DES aesObject;

        public DES DesObject
        {
            get { return aesObject; }
            set { aesObject = value; }
        }


        public DESWrapper(byte[] _aesKey = null, byte[] _aesIV = null)
        {
            if (_aesKey == null)
                DesObject = GenrentAes();
            else
            {
                DesObject = GenrentAes();
                DesObject.Key = _aesKey;
                DesObject.IV = _aesIV;
            }

        }
        public byte[] SymmetricDecrypt(byte[] chiperText)
        {
            ICryptoTransform decrypt = aesObject.CreateDecryptor();
            byte[] output;
            using (MemoryStream memoryStreamDecrypt = new MemoryStream(chiperText))
            {
                using (CryptoStream cryptoStreamDecrypt = new CryptoStream(memoryStreamDecrypt, decrypt, CryptoStreamMode.Read))
                {
                    byte[] buffer = new byte[2048];
                    int lenght = cryptoStreamDecrypt.Read(buffer, 0, 2048);
                    output = new byte[lenght];
                    Array.Copy(buffer, 0, output, 0, lenght);

                }
            }
            return output;
        }

        public byte[] EncryptStringToBytes(byte[] plainText)
        {
            byte[] encryptedText;
            ICryptoTransform encryptor = DesObject.CreateEncryptor();

            using (MemoryStream memoryStreamEncrypt = new MemoryStream())
            {
                using (CryptoStream crytoStreamStreamEncrypt = new CryptoStream(memoryStreamEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    crytoStreamStreamEncrypt.Write(plainText, 0, plainText.Length);
                }
                encryptedText = memoryStreamEncrypt.ToArray();
            }
            return encryptedText;

        }
        public byte[][] GiveAesIVAndKey()
        {
            return new byte[][] { DesObject.Key, DesObject.IV };
        }

        public DES GenrentAes()
        {
            DES des = DES.Create();
            des.Mode = CipherMode.CBC;
            des.Padding = PaddingMode.PKCS7;
            return des;
        }

    }
}
