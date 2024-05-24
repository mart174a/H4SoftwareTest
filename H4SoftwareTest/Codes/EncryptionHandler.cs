using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using System.Text;

namespace H4SoftwareTest.Codes;

public class EncryptionHandler
{
    private readonly IDataProtector _dataProtector;
    private string _privateKey;
    private string _publicKey;
    private readonly HttpClient _httpClient;

    public EncryptionHandler(IDataProtectionProvider dataProtector, HttpClient httpClient)
    {
        _dataProtector = dataProtector.CreateProtector("SuperHemmelig");
        _httpClient = httpClient;


        if (!File.Exists("privateKey.pem"))
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                _privateKey = rsa.ToXmlString(true);
                _publicKey = rsa.ToXmlString(false);

                File.WriteAllText("privateKey.pem", _privateKey);
                File.WriteAllText("publicKey.pem", _publicKey);
            }
        }
        else
        {
            _privateKey = File.ReadAllText("privateKey.pem");
            _publicKey = File.ReadAllText("publicKey.pem");
        }
    }

    #region Symetric encryption

    public string EncryptSymetrisc(string txtToEncrypt) => _dataProtector.Protect(txtToEncrypt);

    public string DecryptSymetrisc(string txtToDecrypt) => _dataProtector.Unprotect(txtToDecrypt);

    #endregion

    #region Asymetric encryption

    public string EncryptAsymetrisc(string txtToEncrypt)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(_publicKey);

        byte[] txtToEncryptAsByteArry = Encoding.UTF8.GetBytes(txtToEncrypt);
        byte[] encryptedValue = rsa.Encrypt(txtToEncryptAsByteArry, true);
        string encryptedValueAsString = Convert.ToBase64String(encryptedValue);

        return encryptedValueAsString;
    }

    public string DecryptAsymetrisc(string txtToDecrypt)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(_privateKey);

        byte[] byteArrayTextToDecrypt = Convert.FromBase64String(txtToDecrypt);
        byte[] decryptedDataAsByteArray = rsa.Decrypt(byteArrayTextToDecrypt, true);
        string decryptedDataAsString = Encoding.UTF8.GetString(decryptedDataAsByteArray);

        return decryptedDataAsString;
    }

    #endregion
}
