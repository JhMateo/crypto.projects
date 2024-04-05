using System.Security.Cryptography;
using System.Text.Json;

namespace crypto.projects
{
    public class Keys
    {
        public List<KeyPair> keyPairs;

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
                        PublicKey = Convert.ToBase64String(publicKey.Modulus),
                        Parameters = new Dictionary<string, byte[]>()
                        {
                            { "D", privateKey.D },
                            { "P", privateKey.P },
                            { "Q", privateKey.Q },
                            { "Modulus", privateKey.Modulus },
                            { "DQ", privateKey.DQ },
                            { "DP", privateKey.DP },
                            { "Exponent", publicKey.Exponent },
                            { "InverseQ", privateKey.InverseQ }
                        }
                    });

                    // Guardar el diccionario en un archivo JSON
                    SaveToJson();
                    Console.WriteLine("Par de claves generadas y guardadas en keys.json\n");
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine($"Error de criptografía: {e.Message}\n");
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

        public void LoadFromJson()
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
        public Dictionary<string, byte[]> Parameters {  get; set; }
    }
}
