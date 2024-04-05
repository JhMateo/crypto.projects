using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace crypto.projects
{
    internal class Verify
    {
        public void VerifySignature(Keys keys)
        {
            // Obtener archivos ZIP disponibles para verificar
            string[] zipFiles = GetZipFiles();

            // Verificar si hay archivos ZIP disponibles
            if (zipFiles.Length == 0)
            {
                Console.WriteLine("No hay archivos ZIP disponibles para verificar.\n");
                return;
            }

            // Mostrar archivos ZIP disponibles para verificar
            DisplayZipFiles(zipFiles);

            // Elegir un archivo ZIP para verificar
            int zipIndex = ChooseZipFile(zipFiles);
            if (zipIndex == -1)
                return;

            // Mostrar contenido del archivo ZIP seleccionado
            DisplayZipContent(zipFiles[zipIndex]);

            // Mostrar llaves públicas disponibles para elegir una para verificar la firma
            Sign sign = new Sign();
            sign.DisplayPublicKeys(keys);

            // Elegir una llave pública para verificar la firma
            int keyIndex = sign.ChoosePublicKey(keys);
            if (keyIndex == -1)
                return;

            // Obtener el par de claves seleccionado
            KeyPair selectedKeyPair = keys.keyPairs[keyIndex];

            try
            {
                // Convertir los parámetros de la llave a RSAParameters
                RSAParameters publicKeyParams = sign.ConvertToRSAParameters(selectedKeyPair.Parameters);

                // Leer la firma y el mensaje del archivo ZIP
                byte[] signature, messageBytes;
                ReadZipContent(zipFiles[zipIndex], out signature, out messageBytes);

                // Verificar la firma utilizando la llave pública y los datos del archivo ZIP
                bool verified = VerifySignature(publicKeyParams, messageBytes, signature);
                PrintVerificationResult(verified);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error al verificar la firma: {ex.Message}\n");
            }
        }

        private string[] GetZipFiles()
        {
            // Obtener archivos ZIP disponibles en el directorio actual
            return Directory.GetFiles(Directory.GetCurrentDirectory(), "firma_*.zip");
        }

        private void DisplayZipFiles(string[] zipFiles)
        {
            // Mostrar archivos ZIP disponibles para verificar
            Console.WriteLine("Archivos ZIP disponibles para verificar:");
            for (int i = 0; i < zipFiles.Length; i++)
            {
                Console.WriteLine($"{i}. {Path.GetFileName(zipFiles[i])}");
            }
        }

        private int ChooseZipFile(string[] zipFiles)
        {
            // Elegir un archivo ZIP para verificar
            Console.WriteLine("\nIngrese el número del archivo ZIP que desea verificar:");
            string zipChoice = Console.ReadLine();

            int zipIndex;
            if (!int.TryParse(zipChoice, out zipIndex) || zipIndex < 0 || zipIndex >= zipFiles.Length)
            {
                Console.WriteLine("Error: Selección de archivo ZIP no válida. Por favor elige un número válido.");
                return -1;
            }

            return zipIndex;
        }

        private void DisplayZipContent(string zipFile)
        {
            // Mostrar contenido del archivo ZIP seleccionado
            using (ZipArchive zipArchive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in zipArchive.Entries)
                {
                    if (entry.FullName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                    {
                        if (entry.FullName.Equals("message.txt", StringComparison.OrdinalIgnoreCase) || entry.FullName.Equals("publicKey.txt", StringComparison.OrdinalIgnoreCase))
                        {
                            using (StreamReader streamReader = new StreamReader(entry.Open()))
                            {
                                string content = streamReader.ReadToEnd();
                                Console.WriteLine($"{entry.FullName}: {content}");
                            }
                        }
                    }
                }
            }
        }

        private void ReadZipContent(string zipFile, out byte[] signature, out byte[] messageBytes)
        {
            // Leer la firma y el mensaje del archivo ZIP
            signature = null;
            messageBytes = null;

            using (ZipArchive zipArchive = ZipFile.OpenRead(zipFile))
            {
                foreach (ZipArchiveEntry entry in zipArchive.Entries)
                {
                    if (entry.FullName.Equals("signature.txt", StringComparison.OrdinalIgnoreCase))
                    {
                        using (BinaryReader reader = new BinaryReader(entry.Open()))
                        {
                            signature = reader.ReadBytes((int)entry.Length);
                        }
                    }
                    else if (entry.FullName.Equals("message.txt", StringComparison.OrdinalIgnoreCase))
                    {
                        using (StreamReader streamReader = new StreamReader(entry.Open()))
                        {
                            string message = streamReader.ReadToEnd();
                            messageBytes = Encoding.UTF8.GetBytes(message);
                        }
                    }
                }
            }
        }

        private bool VerifySignature(RSAParameters publicKeyParams, byte[] messageBytes, byte[] signature)
        {
            // Verificar la firma utilizando la llave pública
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKeyParams);
                return rsa.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
        }

        private void PrintVerificationResult(bool verified)
        {
            // Imprimir el resultado de la verificación
            if (verified)
            {
                Console.WriteLine("La firma es válida.\n");
            }
            else
            {
                Console.WriteLine("La firma es inválida.\n");
            }
        }
    }
}
