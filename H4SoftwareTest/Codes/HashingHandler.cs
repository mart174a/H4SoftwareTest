using BCrypt.Net;
using System.Security.Cryptography;
using System.Text;

namespace H4SoftwareTest.Codes;

public class HashingHandler
{
    public enum HashedValueFormats
    {
        SimpleString,
        ByteArrray,
        BitString,
        UtfString,
        HexadecimalString
    }

    public dynamic MD5Hashing(string txtToHash, HashedValueFormats format)
    {
        MD5 md5 = MD5.Create();
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        byte[] hashedValue = md5.ComputeHash(txtToHashAsByteArray);

        return FormatHashedValue(hashedValue, format);
    }

    public string SHA2Hashing(string txtToHash, HashedValueFormats format)
    {
        SHA256 sha256 = SHA256.Create();
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        byte[] hashedValue = sha256.ComputeHash(txtToHashAsByteArray);

        return FormatHashedValue(hashedValue, format);
    }

    public string HMACHashing(string txtToHash, string key ,HashedValueFormats format)
    {
        byte[] myKey = Encoding.ASCII.GetBytes(key);
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);

        HMACSHA256 hmac = new HMACSHA256();
        hmac.Key = myKey;

        byte[] hashedValue = hmac.ComputeHash(txtToHashAsByteArray);

        return FormatHashedValue(hashedValue, format);
    }

    public string PBKDF2Hashing(string txtToHash, string salt ,HashedValueFormats format)
    {
        byte[] txtToHashAsByteArray = Encoding.ASCII.GetBytes(txtToHash);
        byte[] saltAsbytes = Encoding.ASCII.GetBytes(salt);
        var hashAlgo = new HashAlgorithmName("SHA256");
        int itirationer = 10;
        int outputLength = 32;

        byte[] hashedValue = Rfc2898DeriveBytes.Pbkdf2(txtToHashAsByteArray, saltAsbytes, itirationer, hashAlgo, outputLength);

        return FormatHashedValue(hashedValue, format);
    }

    public string BCryptHashing(string txtToHash)
    {
        return BCrypt.Net.BCrypt.HashPassword(txtToHash);
    }

    public bool BCryptHashingVerify(string txtToHash, string hashedValue)
    {
        return BCrypt.Net.BCrypt.Verify(txtToHash, hashedValue);
    }


    private dynamic FormatHashedValue(byte[] hashedValue, HashedValueFormats hashedValueFormats)
    {
        switch (hashedValueFormats)
        {
            case HashedValueFormats.SimpleString:
                return Convert.ToBase64String(hashedValue);
            case HashedValueFormats.ByteArrray:
                return hashedValue;
            case HashedValueFormats.BitString:
                return BitConverter.ToString(hashedValue);
            case HashedValueFormats.UtfString:
                return Encoding.UTF8.GetString(hashedValue, 0, hashedValue.Length);
            case HashedValueFormats.HexadecimalString:
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashedValue)
                    sb.Append(b.ToString("X2"));
                return sb.ToString();
            default:
                return null;
        }
    }
}

