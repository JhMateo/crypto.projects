using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace crypto.projects
{
    internal class Sign
    {
        // Contador para generar nombres únicos de archivos ZIP
        int zipCounter = 0;

        public void SignMessage(Keys keys)
        {
            // Verificar la existencia de claves
            if (!CheckKeyExistence(keys))
                return;

            // Mostrar las llaves públicas disponibles
            DisplayPublicKeys(keys);

            // Elegir una llave pública para firmar el mensaje
            int keyIndex = ChoosePublicKey(keys);
            if (keyIndex == -1)
                return;

            // Obtener la llave pública seleccionada
            KeyPair selectedKeyPair = keys.keyPairs[keyIndex];

            // Solicitar al usuario que ingrese el mensaje a firmar
            Console.WriteLine("\n > Escriba el mensaje para firmar:");
            string message = Console.ReadLine();

            // Verificar si se ingresó un mensaje válido
            if (string.IsNullOrWhiteSpace(message))
            {
                Console.WriteLine("Error: No se ingresó ningún mensaje.\n");
                return;
            }

            try
            {
                // Generar la firma del mensaje utilizando la llave privada
                byte[] signature = GenerateSignature(selectedKeyPair, message);

                // Verificar si se generó la firma correctamente
                if (signature == null)
                    return;

                // Comprimir y guardar los archivos de firma, mensaje y clave pública
                CompressAndSaveFiles(signature, message, selectedKeyPair.PublicKey);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al firmar el mensaje: {ex.Message}\n");
            }
        }

        private bool CheckKeyExistence(Keys keys)
        {
            // Verificar la existencia de claves
            if (!File.Exists("keys.json") || keys.keyPairs.Count == 0)
            {
                Console.WriteLine("Error: No se encontraron pares de claves. Por favor genera un par primero.\n");
                return false;
            }
            return true;
        }

        public void DisplayPublicKeys(Keys keys)
        {
            // Mostrar las llaves públicas disponibles
            Console.WriteLine("Llaves públicas disponibles:");
            for (int i = 0; i < keys.keyPairs.Count; i++)
            {
                Console.WriteLine($"{i}. {keys.keyPairs[i].PublicKey}");
            }
        }

        public int ChoosePublicKey(Keys keys)
        {
            // Elegir una llave pública para firmar el mensaje
            Console.WriteLine("\n > Elija una llave pública (Ingrese el número de la llave):");
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
            // Generar la firma del mensaje utilizando la llave privada
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            RSAParameters privateKeyParams = ConvertToRSAParameters(keyPair.Parameters);

            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKeyParams);
                return rsa.SignData(messageBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        public RSAParameters ConvertToRSAParameters(Dictionary<string, byte[]> parameters)
        {
            // Convertir los parámetros de la llave a RSAParameters
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
            // Comprimir y guardar los archivos de firma, mensaje y clave pública en un archivo ZIP
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
            // Obtener un contador único para generar nombres de archivos ZIP
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
