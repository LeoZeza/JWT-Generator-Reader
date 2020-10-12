using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Security.Cryptography;
using System.Text;

namespace JWT_generator_reader
{
    class Program
    {
        private const string secret = "senhaSecretaDoLeonardo";

        static void Main(string[] args)
        {
            var token = GenerateToken();
            var validateToken = ValidateToken(token);
            if (validateToken == true)
            {
                Console.WriteLine(token);
            }
            else
            {
                Console.WriteLine("The token is invalid!");
            }
        }

        public static string GenerateToken()
        {
            var header = new
            {
                typ = "JWT",
                alg = "HS256"
            };

            var payload = new
            {
                user = "leonardo",
                password = "11785932-265a-5498-f335-qw6869ghb68a"
            };

            //Convert the JSON Objects to base64
            byte[] headerBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(header));
            byte[] payloadBytes = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(payload));
            var b64_header = Base64UrlEncoder.Encode(headerBytes);
            var b64_payload = Base64UrlEncoder.Encode(payloadBytes);

            //Create the hash256 with the secrect key
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            HMACSHA256 hmac = new HMACSHA256(secretBytes);

            //Get the hash of header.payload
            var signatureHash = hmac.ComputeHash(Encoding.ASCII.GetBytes(b64_header + "." + b64_payload));

            //Convert the hash result to base64
            var b64_signatureHash = Base64UrlEncoder.Encode(signatureHash);

            //Concat header.payload.signature
            var token = b64_header + "." + b64_payload + "." + b64_signatureHash;

            return token;
        }

        private static bool ValidateToken(string token)
        {

            var tokenParts = token.Split('.');
            var header = tokenParts[0];
            var payload = tokenParts[1];
            var signature = tokenParts[2];
                     
            //Creates the hash with the secret key
            var secretBytes = Encoding.UTF8.GetBytes(secret);
            HMACSHA256 hmac = new HMACSHA256(secretBytes);

            //Calc hash of the concatenation (header.payload) that comes from JWT using HS256
            var encoded_signature = header + "." + payload;
            var signatureHash = hmac.ComputeHash(Encoding.ASCII.GetBytes(encoded_signature));

            //Cod the result in base64
            var b64_signature_checker = Base64UrlEncoder.Encode(signatureHash);

            //Verify if the new signature is equal to the JWT signature
            if (b64_signature_checker == signature)
            {
                return true;
            }
            else return false;
        }
    } 
}

