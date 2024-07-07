using System.Security.Cryptography;
using Jose;

class Program
{
    static void Main()
    {
        // The path to the issuer id and key id file is entered
        string ISSUER_ID = "69a6de7a-xxxx-xxxx-xxxx-xxxxxxxxx";
        string KEY_ID = "2W93xxxxxx";

        // The path to the .p8 file is entered
        var privateKeyContent = File.ReadAllText("C:\\Users\\Computer\\Desktop\\AuthKey_2W93xxxxx.p8");
        var privateKeyList = privateKeyContent.Split('\n').ToList();
        var privateKey = privateKeyList.Where((s, i) => i != 0 && i != privateKeyList.Count - 1).Aggregate((agg, s) => agg + s);

        var privateKeyBytes = Convert.FromBase64String(privateKey);
        using (var ecdsa = ECDsa.Create())
        {
            ecdsa.ImportPkcs8PrivateKey(privateKeyBytes, out _);

            //Token expire time is set as 20 minutes. A new one can be produced upon every request.
            var payload = new
            {
                iss = ISSUER_ID,
                exp = DateTimeOffset.UtcNow.AddMinutes(20).ToUnixTimeSeconds(),
                aud = "appstoreconnect-v1"
            };

            IDictionary<string, object> header = new Dictionary<string, object>();
            header.Add("kid", KEY_ID);

            var token = Jose.JWT.Encode(payload, ecdsa, JwsAlgorithm.ES256, extraHeaders: header);

            Console.WriteLine(token);
        }
    }
}