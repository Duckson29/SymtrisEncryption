using System;
using System.Diagnostics;
using System.Text;
using EncryptionLibrary.InterFaces;

namespace AESH4
{
    class Program
    {
        static void Main(string[] args)
        {
            IRSAEncryption rsa = new EncryptionLibrary.EncryptionFactory().CreateIRsaController(true);
            IAesEncryption aes;

            Console.WriteLine("Text to encrytp: ");
            string input = Console.ReadLine();
            Console.WriteLine("Key to use : ");
            string inputKey = Console.ReadLine();
            Console.WriteLine("IV to use: ");
            string inputIV = Console.ReadLine();
            Console.WriteLine("1.To start encryption\n2.to decrypt");
            int inputchose = int.Parse(Console.ReadLine());
            Stopwatch timer = new Stopwatch();
            aes = new EncryptionLibrary.EncryptionFactory().CreateIAesController(Encoding.UTF8.GetBytes(inputKey), Encoding.UTF8.GetBytes(inputIV));
            int runtime = 6;
            byte[] textInByte = Encoding.UTF8.GetBytes(input);
            byte[] encryptedText = new byte[1];
            while (runtime != 0)
            {

                switch (inputchose)
                {
                    case 1:
                        timer.Start();
                        encryptedText = aes.EncryptStringToBytes(textInByte);
                        Console.WriteLine("Encrpted text : " + Convert.ToBase64String(encryptedText));
                        timer.Stop();
                        Console.Write(" Time spent encrrypteding: " + timer.Elapsed.TotalSeconds + "secs");
                        timer.Reset();
                        break;
                    case 2:
                        timer.Start();
                        byte[] decryptedText = aes.SymmetricDecrypt(encryptedText);
                        Console.WriteLine("Decrypted text : " + Encoding.UTF8.GetString(decryptedText));
                        timer.Stop();
                        Console.Write(" Time spent encrrypteding: " + timer.Elapsed.TotalSeconds + "secs");
                        timer.Reset();
                        break;
                }
                Console.WriteLine($"{runtime}1.To start encryption\n2.to decrypt");
                inputchose = int.Parse(Console.ReadLine());
                runtime--;
                
            }


        }
    }
}
