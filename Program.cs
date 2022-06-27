using System.Security.Cryptography;


static AesCryptoServiceProvider AesProvider()
{
    AesCryptoServiceProvider encryptionService = new AesCryptoServiceProvider();
    encryptionService.BlockSize = 128;
    encryptionService.KeySize = 256;
    return encryptionService;
}


async Task<string> Decrypt(string dataAndIV, string decriptionKey)
{
    byte[] key = Convert.FromBase64String(decriptionKey);
    byte[] cypher = Convert.FromBase64String(dataAndIV);
    byte[] iv = cypher.Take(16).ToArray();
    byte[] encryptedData = cypher.Skip(16).ToArray();
    using (AesCryptoServiceProvider encryptionService = AesProvider())
    {
        ICryptoTransform decryptor = (encryptionService).CreateDecryptor(key, iv);
        using (MemoryStream memoryStream = new MemoryStream(encryptedData))
        {
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
            {
                using (StreamReader streamReader = new StreamReader(cryptoStream))
                    return ((TextReader)streamReader).ReadToEnd();
            }
        }
    }
}



string result = await Decrypt("[Secret]", "[Key]");


Console.WriteLine("Password is: " + result);
