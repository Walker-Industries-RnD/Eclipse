using Grpc.Net.Client;
using MagicOnion;
using MagicOnion.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text;
using static Pariah_Cybersecurity.EasyPQC;
using static Secure_Store.Storage;
using static EclipseProject.Security;
using EclipseLCL;
using Microsoft.AspNetCore.Mvc.ModelBinding;


namespace EclipseProject
{
    public class Test
    {
        [SeaOfDirac("AddNumbers", null, typeof(int), typeof(int), typeof(int))]
        public static int AddNumbers(int a, int b)
        {
            return a + b;
        }

        [SeaOfDirac("SubtractNumbers", null, typeof(int), typeof(int), typeof(int))]
        public static int SubtractNumbers(int a, int b)
        {
            return a - b;
        }
    }
    public class MainTest
    {

        public static async Task Main()
        {
            EclipseServer.RunServer();

            try
            {
                // Client can connect now
                using var channel = GrpcChannel.ForAddress("http://127.0.0.1:5000");
                var api = MagicOnionClient.Create<IDiracService>(channel);

                // enrollment, create clientId/PSK and SecureStore them. server will have access if it's with the same user
                SecureRandom rand = new SecureRandom();
                byte[] PSK = new byte[32];
                string clientId = Guid.NewGuid().ToString();

                rand.NextBytes(PSK);
                SecureStore.Set(clientId, PSK);

                Dictionary<string, byte[]> pubKey = await api.EnrollAsync("demo", clientId);

                // handshake begin
                var secretResult = Keys.CreateSecret(pubKey);
                var sharedSecret = secretResult.key;
                var cipher = secretResult.text;
                byte[] nonceC = new byte[16];

                rand.NextBytes(nonceC);
                var serverResp = await api.BeginHandshakeAsync(clientId, cipher, nonceC);

                var keys = PrepareKeys(PSK, nonceC, serverResp.nonceS, sharedSecret);

                byte[] transcriptHash = SHA256.HashData(ByteArrayExtensions.Combine(Encoding.UTF8.GetBytes(clientId), cipher, nonceC, serverResp.nonceS, serverResp.sessionId, BitConverter.GetBytes(serverResp.epoch)));

                AeadChannel clientChannel = new AeadChannel(keys.k_c2s, serverResp.sessionId, clientId, 1, new Transcript(transcriptHash, "client-finished"));
                AeadChannel serverChannel = new AeadChannel(keys.k_s2c, serverResp.sessionId, clientId, 1, new Transcript(transcriptHash, "server-finished"));

                if (clientChannel.transcript.proof == null || serverChannel.transcript.proof == null)
                {
                    throw new Exception("Invalid HMAC proof");
                }

                byte[] serverTranscriptRaw = await api.FinishHandshakeAsync(clientId, clientChannel.transcript.proof);

                for (int i = 0; i < serverTranscriptRaw.Length; i++)
                {
                    if (serverTranscriptRaw[i] != serverChannel.transcript.proof[i])
                    {
                        throw new Exception("Incorrect transcript HMAC");
                    }
                }
                Dictionary<string, int> payload = new Dictionary<string, int>();
                payload.Add("a", 2);
                payload.Add("b", 62);

                byte[] serializedEnv = clientChannel.PackAndEncrypt("AddNumbers", payload);
                byte[] serializedResp = await api.InvokeAsync(serializedEnv);
                object finalResults = serverChannel.UnpackResponse<object>(serializedResp);

                Console.WriteLine($"Response received.\nCONTENT: {finalResults}");

                bool success = await api.FinishAsync(clientChannel.PackAndEncrypt<bool>("terminate", true));
                Console.WriteLine($"Terminating connection. Success: {success}");

            }
            catch (Exception e)
            {
                Console.WriteLine($"Error: {e.Message}");
            }
        }
    }
}