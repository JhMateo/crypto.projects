using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace crypto.projects
{
    internal class Sign
    {
        int zipCounter = 0;

        public void SignMessage(Keys keys)
        {
            if (!CheckKeyExistence(keys))
                return;

            DisplayPublicKeys(keys);

            int keyIndex = ChoosePublicKey(keys);
            if (keyIndex == -1)
                return;

            KeyPair selectedKeyPair = keys.keyPairs[keyIndex];

            Console.WriteLine("\n > Escriba el mensaje para firmar:");
            string message = Console.ReadLine();

            if (string.IsNullOrWhiteSpace(message))
            {
                Console.WriteLine("Error: No se ingresó ningún mensaje.\n");
                return;
            }

            try
            {
                byte[] signature = GenerateSignature(selectedKeyPair, message);

                if (signature == null)
                    return;

                CompressAndSaveFiles(signature, message, selectedKeyPair.PublicKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al firmar el mensaje: {ex.Message}\n");
                // Registrar el error con más detalles
            }
        }

        private bool CheckKeyExistence(Keys keys)
        {
            if (!File.Exists("keys.json") || keys.keyPairs.Count == 0)
            {
                Console.WriteLine("Error: No se encontraron pares de claves. Por favor genera un par primero.\n");
                return false;
            }
            return true;
        }

        private void DisplayPublicKeys(Keys keys)
        {
            Console.WriteLine("Llaves públicas disponibles:");
            for (int i = 0; i < keys.keyPairs.Count; i++)
            {
                Console.WriteLine($"{i}. {keys.keyPairs[i].PublicKey}");
            }
        }

        private int ChoosePublicKey(Keys keys)
        {
            Console.WriteLine("\n > Elija una llave pública para firmar el mensaje (Ingrese el número de la llave):");
            string keyChoice = Console.ReadLine();

            if (!int.TryParse(keyChoice, out int keyIndex) || keyIndex < 0 || keyIndex >= keys.keyPairs.Count)
            {
                Console.WriteLine("Error: Selección de clave no válida. Por favor elige un número válido.\n");
                return -1;
            }

            return keyIndex;
        }

        private byte[] GenerateSignature(KeyPair keyPair, string message)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            RSAParameters privateKeyParams = ConvertToRSAParameters(keyPair.Parameters);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKeyParams);
                return rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        private RSAParameters ConvertToRSAParameters(Dictionary<string, byte[]> parameters)
        {
            return new RSAParameters
            {
                D = parameters["D"],
                P = parameters["P"],
                Q = parameters["Q"],
                Modulus = parameters["Modulus"],
                DQ = parameters["DQ"],
                DP = parameters["DP"],
                Exponent = parameters["Exponent"],
                InverseQ = parameters["InverseQ"]
            };
        }

        private void CompressAndSaveFiles(byte[] signature, string message, string publicKey)
        {
            try
            {
                // Guardar la firma, el mensaje y la llave publica en un archivo
                File.WriteAllBytes("signature.txt", signature);
                File.WriteAllText("message.txt", message);
                File.WriteAllText("publicKey.txt", publicKey);

                // Crear un nombre de archivo ZIP único
                string zipFileName = $"firma_{GetUniqueZipCounter()}.zip";

                // Crear un archivo ZIP para comprimir los archivos
                using (ZipArchive zip = ZipFile.Open(zipFileName, ZipArchiveMode.Create))
                {
                    zip.CreateEntryFromFile("signature.txt", "signature.txt");
                    zip.CreateEntryFromFile("message.txt", "message.txt");
                    zip.CreateEntryFromFile("publicKey.txt", "publicKey.txt");
                }

                // Eliminar los archivos temporales
                File.Delete("signature.txt");
                File.Delete("message.txt");
                File.Delete("publicKey.txt");

                Console.WriteLine($"\nFirma, mensaje y llave pública comprimidos en {zipFileName}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al comprimir y guardar los archivos: {ex.Message}\n");
            }
        }
        private int GetUniqueZipCounter()
        {
            int counter = zipCounter;
            while (File.Exists($"firma_{counter}.zip"))
            {
                counter++;
            }
            zipCounter = counter + 1;
            return counter;
        }
    }
}
