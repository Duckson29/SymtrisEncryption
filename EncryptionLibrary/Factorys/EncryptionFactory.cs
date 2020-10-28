using System;
using System.Collections.Generic;
using System.Text;
using EncryptionLibrary.InterFaces;

namespace EncryptionLibrary
{
    public class EncryptionFactory
    {
        /// <summary>
        /// creates a new instance of the asyncmrtiKey Class
        /// </summary>
        /// <param name="createnewKeys">wheter or not to create new keypairs</param>
        /// <returns></returns>
        public IRSAEncryption CreateIRsaController(bool createnewKeys)
        {
            return new RsaEncryptionController(createnewKeys);
        }
        /// <summary>
        /// Creates a encryptencontroller white a new key
        /// </summary>
        /// <returns></returns>
        public IAesEncryption CreateIAesController()
        {
            return CreateIAesController(null,null);
        }
        /// <summary>
        /// Creates a Encryptioncontroller with the key that is giving.
        /// </summary>
        /// <param name="aesKey"></param>
        /// <param name="aesIV"></param>
        /// <returns></returns>
        public IAesEncryption CreateIAesController(byte[] aesKey , byte[] aesIV)
        {
            return new SymmetricKeyController(aesKey,aesIV);
        }
        public IHash CreateIHash() 
        {
            return new MD5Hashing();
        }
    }
}
