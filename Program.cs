using crypto.projects;
using System;
using System.IO;
using System.Security.Cryptography;


class Program
{
    static void Main()
    {        
        while (true)
        {
            // Inicializar parametros
            Keys keys = new Keys();
            Sign sign = new Sign();

            // Menú
            Console.WriteLine("---------------- MENÚ ----------------");
            Console.WriteLine("1. Generar par de claves pública y privada");
            Console.WriteLine("2. Firmar el archivo de texto");
            Console.WriteLine("3. Verificar la firma");
            Console.WriteLine("4. Salir");

            Console.WriteLine("\n > Ingresa una opción:");
            int opcion = Convert.ToInt32(Console.ReadLine());
            Console.WriteLine("\n");

            switch (opcion)
            {
                case 1:
                    keys.GeneratePairKeys();
                    break;
                case 2:
                    sign.SignMessage(keys);
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
        