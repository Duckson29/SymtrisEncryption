using System;
using System.Collections.Generic;
using System.Text;

namespace EncryptionLibrary.InterFaces
{
    public interface IAesEncryption
    {
        byte[] SymmetricDecrypt(byte[] chiperText);
        byte[] EncryptStringToBytes(byte[] plainText);
        byte[][] GiveAesIVAndKey();
    }
}
