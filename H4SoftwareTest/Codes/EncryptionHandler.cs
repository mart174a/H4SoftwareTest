using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
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
        _dataProtector = dataProtector.CreateProtector("NielsErMinFavoritLære");

        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        _privateKey = rsa.ToXmlString(true);
        _publicKey = rsa.ToXmlString(false);
        _httpClient = httpClient;
    }

    #region Symetric encryption

    public string EncryptSymetrisc(string txtToEncrypt) => _dataProtector.Protect(txtToEncrypt);

    public string DecryptSymetrisc(string txtToDecrypt) => _dataProtector.Unprotect(txtToDecrypt);

    #endregion

    #region Asymetric encryption

    //public async Task<string> EncryptAsymetriscParent(string txtToEncrypt)
    //{
    //    string[] data = new string[2] { txtToEncrypt, _publicKey };
    //    string serializedValue = JsonConvert.SerializeObject(data);
    //    StringContent content = new StringContent(serializedValue, System.Text.Encoding.UTF8, "application/json");
    //    var response = await _httpClient.PostAsync("https://localhost:7171/api/Encrypt", content);
    //    string encryptedValue = await response.Content.ReadAsStringAsync();
    //    return encryptedValue;
    //}

    // Dette kryptering kode er det som ligger i web api:
    public string EncryptAsymetrisc(string txtToEncrypt)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(_publicKey);

        byte[] txtToEncryptAsByteArry = System.Text.Encoding.UTF8.GetBytes(txtToEncrypt);
        byte[] encryptedValue = rsa.Encrypt(txtToEncryptAsByteArry, true);
        string encryptedValueAsString = Convert.ToBase64String(encryptedValue);

        return encryptedValueAsString;
    }

    public string DecryptAsymetrisc(string txtToDecrypt)
    {
        RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
        rsa.FromXmlString(_privateKey);

        byte[] txtToDecryptAsByteArry = Convert.FromBase64String(txtToDecrypt); // System.Text.Encoding.UTF8.GetBytes(txtToDecrypt);
        byte[] encryptedValue = rsa.Decrypt(txtToDecryptAsByteArry, true);
        string encryptedValueAsString = System.Text.Encoding.UTF8.GetString(encryptedValue);  // Convert.ToBase64String(encryptedValue);

        return encryptedValueAsString;
    }

    #endregion
}
