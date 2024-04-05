using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace crypto.projects
{
    internal class Verify
    {
        public void VerifySignature(Keys keys)
        {
            // Dar la opción para elegir un archivo ZIP de los que ya existen
            string[] zipFiles = Directory.GetFiles(Directory.GetCurrentDirectory(), "firma_*.zip");
            if (zipFiles.Length == 0)
            {
                Console.WriteLine("No hay archivos ZIP disponibles para verificar.");
                return;
            }

            Console.WriteLine("Archivos ZIP disponibles para verificar:");
            for (int i = 0; i < zipFiles.Length; i++)
            {
                Console.WriteLine($"{i}. {Path.GetFileName(zipFiles[i])}");
            }

            Console.WriteLine("\nIngrese el número del archivo ZIP que desea verificar:");
            string zipChoice = Console.ReadLine();

            int zipIndex;
            if (!int.TryParse(zipChoice, out zipIndex) || zipIndex < 0 || zipIndex >= zipFiles.Length)
            {
                Console.WriteLine("Error: Selección de archivo ZIP no válida. Por favor elige un número válido.");
                return;
            }

            // Segundo Paso: Mostrar el mensaje y la llave pública que hay en el archivo ZIP seleccionado
            using (ZipArchive zipArchive = ZipFile.OpenRead(zipFiles[zipIndex]))
            {
                foreach (ZipArchiveEntry entry in zipArchive.Entries)
                {
                    if (entry.FullName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                    {
                        if(entry.FullName.Equals("message.txt", StringComparison.OrdinalIgnoreCase) || entry.FullName.Equals("publicKey.txt", StringComparison.OrdinalIgnoreCase))
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
            Console.WriteLine();

            // Utilizar DisplayPublicKeys de Sign para elegir una llave pública para verificar la firma
            Sign sign = new Sign();
            sign.DisplayPublicKeys(keys);

            // Utilizar ChoosePublicKey de Sign para elegir la llave
            int keyIndex = sign.ChoosePublicKey(keys);
            if (keyIndex == -1)
                return;

            KeyPair selectedKeyPair = keys.keyPairs[keyIndex];

            try
            {
                // Convertir los parámetros de la llave con ConvertToRSAParameters de Sign
                RSAParameters publicKeyParams = sign.ConvertToRSAParameters(selectedKeyPair.Parameters);

                // Verificar la firma
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(publicKeyParams);

                    // Leer la firma y el mensaje del archivo ZIP
                    byte[] signature = null, messageBytes = null;
                    using (ZipArchive zipArchive = ZipFile.OpenRead(zipFiles[zipIndex]))
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

                    bool verified = rsa.VerifyData(messageBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
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
            catch (Exception ex)
            {
                Console.WriteLine($"Error al verificar la firma: {ex.Message}\n");
                // Registrar el error con más detalles
            }
        }
    }
}
