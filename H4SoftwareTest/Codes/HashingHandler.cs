using BCrypt.Net;
using System.Security.Cryptography;
using System.Text;

namespace H4SoftwareTest.Codes;

public class HashingHandler
{
    public dynamic MD5Hashing(string txtToHash, string returnType)
    {
        MD5 md5 = MD5.Create();
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        byte[] hashedValue = md5.ComputeHash(txtToHashAsByteArray);

        if (returnType == "string")
        {
            string hashedValueAsString = Convert.ToBase64String(hashedValue);
            return hashedValueAsString;
        }
        else if (returnType == "byteArray")
        {
            return hashedValue;
        }
        else
            return null;
    }

    public string SHA2Hashing(string txtToHash)
    {
        SHA256 sha256 = SHA256.Create();
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        byte[] hashedValue = sha256.ComputeHash(txtToHashAsByteArray);

        string hashedValueAsString = Convert.ToBase64String(hashedValue);
        return hashedValueAsString;
    }

    public string HMACHashing(string txtToHash)
    {
        byte[] myKey = Encoding.ASCII.GetBytes("NielsErMinFavoritLære");
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);

        HMACSHA256 hmac = new HMACSHA256();
        hmac.Key = myKey;

        byte[] hashedValue = hmac.ComputeHash(txtToHashAsByteArray);
        string hashedValueAsString = Convert.ToBase64String(hashedValue);
        return hashedValueAsString;
    }

    public string PBKDF2Hashing(string txtToHash)
    {
        byte[] salt = Encoding.ASCII.GetBytes("NielsErMinFavoritLære");
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        var hashAlgo = new HashAlgorithmName("SHA256");
        int itirationer = 10;
        int outputLength = 32;

        byte[] hashedValue = Rfc2898DeriveBytes.Pbkdf2(txtToHashAsByteArray, salt, itirationer, hashAlgo, outputLength);
        string hashedValueAsString = Convert.ToBase64String(hashedValue);
        return hashedValueAsString;
    }

    public string BCryptHashing(string txtToHash)
    {
        string salt = BCrypt.Net.BCrypt.GenerateSalt();
        bool enhancedEntropi = true;
        HashType hashType = HashType.SHA256;
        return BCrypt.Net.BCrypt.HashPassword(txtToHash, salt, enhancedEntropi, hashType);
    }

    public bool BCryptHashingVerify(string txtToHash, string hashedValueAsString)
    {
        return BCrypt.Net.BCrypt.Verify(txtToHash, hashedValueAsString, true, HashType.SHA256);
    }
}

