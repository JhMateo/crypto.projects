using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace crypto.projects
{
    public class Keys
    {
        private List<KeyPair> keyPairs;

        public Keys()
        {
            keyPairs = new List<KeyPair>();
            LoadFromJson(); // Cargar claves existentes desde el archivo JSON al inicializar
        }

        public void GeneratePairKeys()
        {
            try
            {
                // Crear una instancia de la clase RSACryptoServiceProvider
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    Console.WriteLine("Generando par de claves...");

                    // Generar el par de claves pública y privada
                    RSAParameters privateKey = rsa.ExportParameters(true);
                    RSAParameters publicKey = rsa.ExportParameters(false);

                    int nextIndex = keyPairs.Count;

                    // Agregar el nuevo par de claves a la lista existente
                    keyPairs.Add(new KeyPair
                    {
                        Key = nextIndex.ToString(),
                        PrivateKey = Convert.ToBase64String(privateKey.D),
                        PublicKey = Convert.ToBase64String(publicKey.Modulus)
                    });;;

                    // Guardar el diccionario en un archivo JSON
                    SaveToJson();
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"Error de criptografía: {e.Message}");
            }
        }

        private void SaveToJson()
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true
            };

            // Serializar la lista de pares de claves a JSON
            string json = JsonSerializer.Serialize(new { keys = keyPairs }, options);

            // Guardar el JSON en un archivo
            File.WriteAllText("keys.json", json);
        }

        private void LoadFromJson()
        {
            try
            {
                if (File.Exists("keys.json"))
                {
                    // Leer el JSON desde el archivo
                    string json = File.ReadAllText("keys.json");

                    // Deserializar el JSON a una lista de pares de claves
                    var jsonData = JsonSerializer.Deserialize<Dictionary<string, List<KeyPair>>>(json);

                    // Actualizar la lista de claves
                    keyPairs = jsonData["keys"];
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error al cargar las claves desde el archivo JSON: {e.Message}");
            }
        }
    }

    public class KeyPair
    {
        public string Key { get; set; }
        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
    }
}
