using EclipseProject;
using MagicOnion;
using MagicOnion.Server;
using Org.BouncyCastle.Asn1.Cms;
using Pariah_Cybersecurity;
using System.Security.Cryptography;
using static EclipseProject.Security;


public interface IDiracService : IService<IDiracService>
{
    UnaryResult<Dictionary<string, byte[]>> EnrollAsync(string clientName, string clientId);
    UnaryResult<(byte[] nonceS, byte[] sessionId, uint epoch)> BeginHandshakeAsync(string clientId, byte[] cipher, byte[] nonceC);
    UnaryResult<byte[]> FinishHandshakeAsync(string clientId, byte[] clientTranscript);
    UnaryResult<byte[]> InvokeAsync(byte[] serializedEnv);
}