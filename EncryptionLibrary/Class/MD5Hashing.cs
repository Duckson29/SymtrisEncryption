using System;
using System.Text;
using System.Security.Cryptography;
using EncryptionLibrary.InterFaces;

namespace EncryptionLibrary
{
    class MD5Hashing : IHash
    {
        MD5 md5Hash = MD5.Create();
        StringBuilder stringbulider = new StringBuilder();

        /// <summary>
        /// Compute a hash form the input and returns a uppercase string.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public string ComputeHash(string input)
        {
            byte[] hashedInputBytes = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));
            foreach (byte bit in hashedInputBytes)
                stringbulider.Append(bit.ToString("X2"));
            return stringbulider.ToString();
        }

        /// <summary>
        /// Compares two strings, Note it converts to lowercase.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="hashedInput"></param>
        /// <returns></returns>
        public bool CompareHash(string input, string hashedInput)
        {
            StringComparer com = StringComparer.OrdinalIgnoreCase;

            if (com.Compare(ComputeHash(input), hashedInput) == 0)
                return true;
            else
                return false;
        }
    }
}
