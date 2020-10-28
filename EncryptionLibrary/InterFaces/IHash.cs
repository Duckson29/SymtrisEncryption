using System;
using System.Collections.Generic;
using System.Text;

namespace EncryptionLibrary.InterFaces
{
    public interface IHash
    {
        /// <summary>
        /// Compares two string inputs.
        /// </summary>
        /// <param name="input"></param>
        /// <param name="hashedInput"></param>
        /// <returns></returns>
        bool CompareHash(string input, string hashedInput);

        /// <summary>
        /// Gives a utf8 hashed version of the input.
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        string ComputeHash(string input);
    }
}
