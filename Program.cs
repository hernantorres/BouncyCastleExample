using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace BouncyCastleExample
{
    class Program
    {
        static void Main(string[] args)
        { 
            // Console.WriteLine("Hello World!");

            // Variables declaration
            string SrcData;
            byte[] tmpSource;
            // byte[] tempHash;
            
            // Retrieve message
            Console.WriteLine("Ingrese cualquier texto: ");
            SrcData = Console.ReadLine();

            // Create byte array from source data
            tmpSource = Encoding.ASCII.GetBytes(SrcData);
            Console.WriteLine();
            Console.WriteLine("Pareja de llaves generandose...\n");
             
            // RSAKeyPairGenerator
            RsaKeyPairGenerator rsaKeyPairGen = new RsaKeyPairGenerator();
            rsaKeyPairGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048) );
            AsymmetricCipherKeyPair keyPair = rsaKeyPairGen.GenerateKeyPair();

            // Extract public and private key
            RsaKeyParameters PrivateKey = (RsaKeyParameters)keyPair.Private;
            RsaKeyParameters PublicKey = (RsaKeyParameters)keyPair.Public;

            // Print public key in PEM format
            TextWriter textWriter1 = new StringWriter();
            PemWriter pemWriter1 = new PemWriter(textWriter1);
            pemWriter1.WriteObject(PublicKey);
            pemWriter1.Writer.Flush();
            string printPublicKey = textWriter1.ToString();
            Console.WriteLine("La llave pública es: {0}", printPublicKey);
            Console.WriteLine();


            // Encryption
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine());
            cipher.Init(true, PublicKey);
            byte[] cipherText = cipher.ProcessBlock(tmpSource, 0, tmpSource.Length);
            string result = Encoding.UTF8.GetString(cipherText);
            Console.WriteLine("Texto cifrado: ");
            Console.WriteLine(result);
            Console.WriteLine();

            Console.WriteLine("¿Quiete descifrar el texto? Presione espacio para cifrarlo, o cualquier otra tecla si no");
            char inputChar = Console.ReadKey().KeyChar;
            if(inputChar == ' ')
                Decryption(cipherText, PrivateKey);
        }

        static void Decryption(byte[] cipherText, RsaKeyParameters PrivateKey)
        {
            IAsymmetricBlockCipher decipher = new OaepEncoding(new RsaEngine());
            decipher.Init(false, PrivateKey);
            byte[] deciphered = decipher.ProcessBlock(cipherText, 0, cipherText.Length);
            string decipheredText = Encoding.UTF8.GetString(deciphered);
            Console.WriteLine();
            Console.WriteLine("Texto decifrado: {0}", decipheredText);
            Console.WriteLine();
        }
    }
}
