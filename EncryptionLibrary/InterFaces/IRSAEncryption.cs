using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace EncryptionLibrary.InterFaces
{
    public interface IRSAEncryption
    {
        byte[] Decryption(byte[] Data, RSAParameters RSAKey);
        byte[] Encryption(byte[] Data, byte[] PublicKey, byte[] Modulus);
        RSAParameters PublicKey { get; }
        RSAParameters PrivateKey { get; }
    }
}
