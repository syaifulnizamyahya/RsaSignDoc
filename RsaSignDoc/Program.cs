using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

public class RsaSignDoc
{
    // Generate a new RSA key pair
    public static void RSAKeyGenerator(ref string publicKey, ref string privateKey)
    {
        using (var rsa = new RSACryptoServiceProvider(2048))
        {
            // Export the public key
            publicKey = rsa.ToXmlString(false);
            // Export the private key
            privateKey = rsa.ToXmlString(true);
        }
    }

    // Convert an object to a byte array
    public static byte[] ObjectToByteArray(object obj)
    {
        if (obj == null)
            return Array.Empty<byte>();

        using (MemoryStream ms = new MemoryStream())
        {
            JsonSerializer.Serialize(ms, obj);
            return ms.ToArray();
        }
    }

    // Convert a byte array to an object
    public static T? ByteArrayToObject<T>(byte[] arrBytes)
    {
        if (arrBytes == null || arrBytes.Length == 0)
            return default;

        string jsonString = Encoding.UTF8.GetString(arrBytes);
        return JsonSerializer.Deserialize<T>(jsonString);
    }

    // Sign data
    public static byte[] SignData(object dataToSign, string privateKey)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.FromXmlString(privateKey);

            // Convert data to bytes
            var dataBytes = ObjectToByteArray(dataToSign);
            var hash = SHA256.Create().ComputeHash(dataBytes);

            var signedBytes = rsa.SignHash(hash, CryptoConfig.MapNameToOID("SHA256"));

            return signedBytes;
        }
    }

    // Verify data
    public static bool VerifyData(object dataToVerify, string publicKey, byte[] signature)
    {
        using (var rsa = new RSACryptoServiceProvider())
        {
            rsa.FromXmlString(publicKey);

            // Convert data to bytes
            var dataBytes = ObjectToByteArray(dataToVerify);
            var hash = SHA256.Create().ComputeHash(dataBytes);

            var oid = CryptoConfig.MapNameToOID("SHA256");

            if (oid != null)
            {
                return rsa.VerifyHash(hash, oid, signature);
            }
            else
            {
                // Handle the case when CryptoConfig.MapNameToOID("SHA256") returns null
                // Maybe throw an exception or handle it in a way that makes sense for your application
                return false;
            }
        }
    }

    public static void Main()
    {
        string publicKey = "";
        string privateKey = "";
        byte[] signedData = Array.Empty<byte>();

        // Generate RSA key pair
        RSAKeyGenerator(ref publicKey, ref privateKey);
        Console.WriteLine("Public Key: \n" + publicKey);
        Console.WriteLine("Private Key: \n" + privateKey);

        // Data to be signed could be anything/type as it will be converted to a byte array
        string data = "This is the data to be signed.";

        // Sign data
        signedData = SignData(data, privateKey);
        Console.WriteLine("Signed Data: \n" + Convert.ToBase64String(signedData));

        // Verify data
        //data = "This is NOT the data to be signed."; // Change this to verify a different data
        bool verified = VerifyData(data, publicKey, signedData);
        Console.WriteLine("Data Verified: \n" + verified);
    }
}
