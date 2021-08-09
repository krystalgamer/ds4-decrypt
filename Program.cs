using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using dnlib.DotNet;
using dnlib.DotNet.Resources;
using System.Linq;



namespace ds4_decrypt
{

    class Program
    {
        static void Main(string[] args)
        {

            if(args.Length != 1)
            {
                Console.WriteLine("Need path to executable updater");
                return;
            }

            var key = new byte[16];
            FileStream keyStream = null;
            try
            {
                keyStream = File.OpenRead("key.bin");
            }
            catch
            {
                Console.WriteLine("You need to create key.bin with the decryption key.");
                return;
            }

            using (var reader = new BinaryReader(keyStream))
                key = reader.ReadBytes(16);

            if(key.Length != 16)
            {
                Console.WriteLine("Key must be 16 bytes");
                return;
            }

            var ctx = ModuleDef.CreateModuleContext();
            var module = ModuleDefMD.Load(args[0], ctx);


            var fws = new List<ResourceElement>();
            foreach (var entry in module.Resources)
            {

                if (entry.ResourceType != ResourceType.Embedded)
                    continue;

                var embedded = (EmbeddedResource)entry;
                var resources = ResourceReader.Read(module, embedded.CreateReader());

                foreach (var resource in resources.ResourceElements)
                {
                    if(resource.ResourceData.Code == ResourceTypeCode.ByteArray)
                        fws.Add(resource);
                }
                    
            }

            if(fws.Count == 0)
            {
                Console.WriteLine("No embedded fws found");
                return;
            }

            var decryptedHeaderHash = new byte[] { 0x83, 0xA9, 0x2E, 0x4E, 0xDC, 0xB7, 0xD3, 0xD9, 0x70, 0xD5, 0xA0, 0xCE, 0x3B, 0xE9, 0xEA, 0x4F };
            foreach(var fw in fws)
            {
                
                var content = (BuiltInResourceData)fw.ResourceData;
                Console.Write($"Working on {fw.Name}...");
                var contentBytes = (byte[])content.Data;

                using (var aes = Aes.Create())
                {
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.None; //assumes it's already 16-bit aligned
                    aes.IV = new byte[16];
                    Array.Fill(aes.IV, (byte)0);
                    aes.Key = key;


                    var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                    using var memoryStream = new MemoryStream(contentBytes);
                    using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
                    using var reader = new BinaryReader(cryptoStream);

                    var decrypted = reader.ReadBytes(contentBytes.Length);

                    var computedHash = MD5.Create().ComputeHash(decrypted[..32]);

                    if (decryptedHeaderHash.SequenceEqual(computedHash))
                    {
                        using var writer = new BinaryWriter(File.Open(fw.Name, FileMode.Create));
                        writer.Write(decrypted);
                        Console.WriteLine("Done");
                    }
                    else
                    {
                        Console.WriteLine("Failed (hash doesn't match)");
                    }

                }
                                
            }

        }
    }
}
