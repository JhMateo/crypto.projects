using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.Linq;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace crypto.projects
{
    internal class Sign
    {
        int zipCounter = 0;

        public void SignMessage(Keys keys)
        {
            // Check if keys.json exists
            if (!File.Exists("keys.json"))
            {
                Console.WriteLine("Error: No se encontraron pares de claves. Por favor genera un par primero.");
                return;
            }

            // Load key pairs from JSON
            keys.LoadFromJson();

            if (keys.keyPairs.Count == 0)
            {
                Console.WriteLine("Error: No se encontraron pares de claves. Por favor genera un par primero.");
                return;
            }

            Console.WriteLine("Llaves públicas disponibles:");
            int i = 0;
            foreach (KeyPair keyPair in keys.keyPairs)
            {
                Console.WriteLine($"{i}. {keyPair.PublicKey}");
                i++;
            }

            // Elegir llave publica
            Console.WriteLine("\n > Elija una llave publica para firmar el mensaje (Ingrese el número de la llave):");
            string keyChoice = Console.ReadLine();

            int keyIndex;
            if (!int.TryParse(keyChoice, out keyIndex) || keyIndex < 0 || keyIndex > (keys.keyPairs.Count - 1))
            {
                Console.WriteLine("Error: Selección de clave no válida. Por favor elige un número válido.");
                return;
            }

            KeyPair selectedKeyPair = keys.keyPairs[keyIndex];
            Console.WriteLine(selectedKeyPair.PublicKey);

            Console.WriteLine("\n > Escriba el mensaje para firmar:");
            string message = Console.ReadLine();

            // Firmar el archivo de texto
            if (message != null)
            {
                byte[] messageBytes = System.Text.Encoding.UTF8.GetBytes(message);
                string publicKey = selectedKeyPair.PublicKey;

                RSAParameters privateKeyParams = new RSAParameters
                {
                    D = selectedKeyPair.Parameters["D"],
                    P = selectedKeyPair.Parameters["P"],
                    Q = selectedKeyPair.Parameters["Q"],
                    Modulus = selectedKeyPair.Parameters["Modulus"],
                    DQ = selectedKeyPair.Parameters["DQ"],
                    DP = selectedKeyPair.Parameters["DP"],
                    Exponent = selectedKeyPair.Parameters["Exponent"],
                    InverseQ = selectedKeyPair.Parameters["InverseQ"]
                };

                try
                {
                    using (RSACryptoServiceProvider rsa2 = new RSACryptoServiceProvider())
                    {
                        rsa2.ImportParameters(privateKeyParams);
                        byte[] sign = rsa2.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                        // Guardar la firma, el mensaje y la llave publica en un archivo
                        File.WriteAllBytes("sign.txt", sign);
                        File.WriteAllText("message.txt", message);
                        File.WriteAllText("publicKey.txt", publicKey);

                        // Crear un nombre de archivo ZIP único
                        string zipFileName = $"firma_{zipCounter}.zip";

                        // Crear un archivo ZIP para comprimir los archivos
                        using (ZipArchive zip = ZipFile.Open(zipFileName, ZipArchiveMode.Create))
                        {
                            // Agregar el archivo de firma
                            zip.CreateEntryFromFile("sign.txt", "sign.txt");

                            // Agregar el archivo de mensaje
                            zip.CreateEntryFromFile("message.txt", "message.txt");

                            // Agregar el archivo de clave pública
                            zip.CreateEntryFromFile("publicKey.txt", "publicKey.txt");
                        }

                        // Eliminar los archivos temporales
                        File.Delete("sign.txt");
                        File.Delete("message.txt");
                        File.Delete("publicKey.txt");

                        Console.WriteLine($"\nFirma, mensaje y llave publica comprimidos en {zipFileName}\n");
                    }
                }
                catch (CryptographicException ex)
                {
                    if (ex.Message.Contains("The key set does not exist"))
                    {
                        Console.WriteLine("Error: El conjunto de claves no existe. Verifique la importación de la clave pública.");
                        // Registrar el error con más detalles
                    }
                    else
                    {
                        Console.WriteLine("Error al firmar el mensaje: " + ex.Message);
                        // Registrar el error con más detalles
                    }
                }

            } else
            {
                Console.WriteLine("No se recibió ningún mensaje...");
            }
        }
    }
}
