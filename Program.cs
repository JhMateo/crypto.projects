using System;
using System.IO;
using System.Security.Cryptography;


class Program
{
    static void Main()
    {
        try
        {
            // Crear una instancia de la clase RSACryptoServiceProvider
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                // Generar el par de claves pública y privada
                var keys = new crypto.projects.Keys();
                keys.GeneratePairKeys();

                // Firmar el archivo de texto
                string mensaje = "Hola, mundo!";
                byte[] mensajeBytes = System.Text.Encoding.UTF8.GetBytes(mensaje);
                byte[] firma = rsa.SignData(mensajeBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Guardar la firma en un archivo
                File.WriteAllBytes("firma.txt", firma);

                // Verificar la firma
                bool verificado = rsa.VerifyData(mensajeBytes, firma, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                if (verificado)
                {
                    Console.WriteLine("La firma es válida.");
                }
                else
                {
                    Console.WriteLine("La firma es inválida.");
                }

                
                while (true)
                {
                    // Menú
                    Console.WriteLine("---------------- MENÚ ----------------");
                    Console.WriteLine("1. Generar el par de claves pública y privada");
                    Console.WriteLine("2. Firmar el archivo de texto");
                    Console.WriteLine("3. Verificar la firma");
                    Console.WriteLine("4. Salir");

                    Console.WriteLine("\n > Ingresa una opción:");
                    int opcion = Convert.ToInt32(Console.ReadLine());
                    Console.WriteLine("\n");

                    switch (opcion)
                    {
                        case 1:
                            var keys2 = new crypto.projects.Keys();
                            keys2.GeneratePairKeys();
                            break;
                        case 2:
                            break;
                        case 3:
                            break;
                        case 4:
                            Console.WriteLine("Saliendo del programa...\n");
                            return;
                        default:
                            Console.WriteLine("Opción no valida");
                            break;
                    }
                }
            }
        }
        catch (CryptographicException e)
        {
            Console.WriteLine($"Error de criptografía: {e.Message}");
        }
    }
}