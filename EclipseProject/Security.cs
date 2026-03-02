using Org.BouncyCastle.Crypto;
using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using MessagePack;

namespace EclipseProject
{
    public static class ByteArrayExtensions
    {
        public static byte[] Combine(params byte[][] arrays)
        {
            int length = arrays.Sum(a => a.Length);
            byte[] result = new byte[length];

            int offset = 0;

            foreach (var array in arrays)
            {
                Buffer.BlockCopy(array, 0, result, offset, array.Length);
                offset += array.Length;
            }

            return result;
        }
    }
    public class Security
    {
        public static (byte[] k_c2s, byte[] k_s2c) PrepareKeys(byte[] PSK, byte[] nonceC, byte[] nonceS, byte[] sharedSecret)
        {
            byte[] salt = ByteArrayExtensions.Combine(PSK, nonceC, nonceS);

            byte[] PRK = HKDF.Extract(HashAlgorithmName.SHA256, sharedSecret, SHA256.HashData(salt));

            byte[] k_c2s = HKDF.Expand(HashAlgorithmName.SHA256, PRK, 32, Encoding.UTF8.GetBytes("c2s"));
            byte[] k_s2c = HKDF.Expand(HashAlgorithmName.SHA256, PRK, 32, Encoding.UTF8.GetBytes("s2c"));

            return (k_c2s, k_s2c);
        }
    public sealed class Transcript
        {
            private byte[] _hash;
            private string _sig;

            public byte[]? proof;

            public Transcript(byte[] hash, string sig)
            {
                _hash = hash;
                _sig = sig;
            }

            public void MakeProof(byte[]? key32)
            {
                if (key32 == null)
                {
                    throw new ArgumentNullException(nameof(key32));
                }

                proof = HMACSHA256.HashData(key32, ByteArrayExtensions.Combine(Encoding.UTF8.GetBytes(_sig), _hash));
                CryptographicOperations.ZeroMemory(_hash);
            }
        }
        public sealed class AeadChannel : IDisposable
        {
            private AesGcm? _aead;
            private byte[]? _sessionId8;
            private readonly string _clientId;

            public uint Epoch { get; private set; }
            public Transcript transcript;

            private uint _sendSeq;
            private uint _recvSeq;

            public AeadChannel(byte[] key32, byte[] sessionId8, string clientId, uint epoch, Transcript t)
            {
                if (clientId is null) throw new ArgumentNullException(nameof(clientId));
                _clientId = clientId;
                transcript = t;

                transcript.MakeProof(key32);

                InitEpoch(key32, sessionId8, epoch);
            }

            /// <summary>
            /// Reinitialize keys/counters for a new epoch (key rotation).
            /// This disposes the old AesGcm instance and resets seq counters.
            /// </summary>
            public void InitEpoch(byte[] key32, byte[] sessionId8, uint epoch)
            {
                if (key32 is null || key32.Length != 32)
                    throw new ArgumentException("key32 must be exactly 32 bytes (AES-256).", nameof(key32));

                if (sessionId8 is null || sessionId8.Length != 8)
                    throw new ArgumentException("sessionId8 must be exactly 8 bytes.", nameof(sessionId8));

                _aead?.Dispose();
                _aead = new AesGcm(key32, tagSizeInBytes: 16);

                _sessionId8 = (byte[])sessionId8.Clone();
                Epoch = epoch;

                _sendSeq = 0;
                _recvSeq = 0;
            }

            public EncryptedEnvelope Encrypt(string method, ReadOnlySpan<byte> plaintext)
            {
                method ??= "";

                checked { _sendSeq += 1; }
                uint seq = _sendSeq;

                byte[] nonce12 = MakeNonce12(_sessionId8, seq);
                byte[] aad = MakeAad(_clientId, Epoch, seq, method);

                byte[] ciphertext = new byte[plaintext.Length];
                byte[] tag = new byte[16];

                _aead.Encrypt(nonce12, plaintext, ciphertext, tag, aad);

                CryptographicOperations.ZeroMemory(nonce12);
                CryptographicOperations.ZeroMemory(aad);

                return new EncryptedEnvelope
                {
                    ClientId = _clientId,
                    Epoch = Epoch,
                    Seq = seq,
                    Method = method,
                    Ciphertext = ciphertext,
                    Tag = tag
                };
            }

            public byte[] Decrypt(EncryptedEnvelope env)
            {
                if (env is null) throw new ArgumentNullException(nameof(env));

                if (!string.Equals(env.ClientId, _clientId, StringComparison.Ordinal))
                    throw new ArgumentException("ClientId mismatch for this channel.");

                if (env.Epoch != Epoch)
                    throw new ArgumentException("Epoch mismatch (likely needs rekey).");

                if (env.Seq != _recvSeq + 1)
                    throw new ArgumentException($"Bad sequence. Expected {_recvSeq + 1}, got {env.Seq}.");

                if (env.Tag is null || env.Tag.Length != 16)
                    throw new ArgumentException("Tag must be 16 bytes.");

                if (env.Ciphertext is null)
                    throw new ArgumentException("Ciphertext missing.");

                byte[] nonce12 = MakeNonce12(_sessionId8, env.Seq);
                byte[] aad = MakeAad(_clientId, Epoch, env.Seq, env.Method ?? "");

                byte[] plaintext = new byte[env.Ciphertext.Length];

                try
                {
                    _aead.Decrypt(nonce12, env.Ciphertext, env.Tag, plaintext, aad);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(nonce12);
                    CryptographicOperations.ZeroMemory(aad);
                }

                _recvSeq = env.Seq;
                return plaintext;
            }

            public void Dispose()
            {
                _aead?.Dispose();
                if (_sessionId8 is not null)
                    CryptographicOperations.ZeroMemory(_sessionId8);
            }

            private static byte[] MakeNonce12(byte[] sessionId8, uint seq)
            {
                byte[] nonce = new byte[12];
                Buffer.BlockCopy(sessionId8, 0, nonce, 0, 8);
                BinaryPrimitives.WriteUInt32BigEndian(nonce.AsSpan(8, 4), seq);
                return nonce;
            }

            private static byte[] MakeAad(string clientId, uint epoch, uint seq, string method)
            {
                // Deterministic encoding. Optimize later if needed.
                byte[] clientBytes = Encoding.UTF8.GetBytes(clientId);
                byte[] methodBytes = Encoding.UTF8.GetBytes(method);

                byte[] aad = new byte[clientBytes.Length + 4 + 4 + methodBytes.Length];

                int o = 0;
                Buffer.BlockCopy(clientBytes, 0, aad, o, clientBytes.Length);
                o += clientBytes.Length;

                BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(o, 4), epoch);
                o += 4;

                BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(o, 4), seq);
                o += 4;

                Buffer.BlockCopy(methodBytes, 0, aad, o, methodBytes.Length);
                return aad;
            }
        }

        [MessagePackObject(keyAsPropertyName: true)]
        public sealed class EncryptedEnvelope
        {
            public string ClientId { get; init; } = "";
            public uint Epoch { get; init; }
            public uint Seq { get; init; }
            public string Method { get; init; } = "";
            public byte[] Ciphertext { get; init; } = Array.Empty<byte>();
            public byte[] Tag { get; init; } = Array.Empty<byte>(); // 16 bytes
        }
        public sealed class SessionState : IDisposable
        {
            public string ClientId { get; }
            public byte[] SessionId8 { get; }           // 8 bytes, not super sensitive
            public uint Epoch { get; private set; }
            public DateTimeOffset LastSeen { get; set; }

            public AeadChannel FromClient { get; }      // holds K_c2s internally
            public AeadChannel ToClient { get; }        // holds K_s2c internally

            public SessionState(string clientId, byte[] sessionId8, uint epoch, AeadChannel fromClient, AeadChannel toClient)
            {
                ClientId = clientId;
                SessionId8 = sessionId8;
                Epoch = epoch;
                FromClient = fromClient;
                ToClient = toClient;
                LastSeen = DateTimeOffset.UtcNow;
            }

            public void Dispose()
            {
                FromClient.Dispose();
                ToClient.Dispose();
                // Optional: zero sessionId8 too
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(SessionId8);
            }
        }

        public sealed class SessionStore : IDisposable
        {
            private readonly ConcurrentDictionary<string, SessionState> _sessions = new();
            private readonly TimeSpan _idleTimeout = TimeSpan.FromMinutes(10);
            private readonly CancellationTokenSource _cts = new();

            public SessionStore()
            {
                _ = CleanupLoopAsync(_cts.Token);
            }

            public bool TryGet(string clientId, out SessionState session)
            {
                if (_sessions.TryGetValue(clientId, out session!))
                {
                    session.LastSeen = DateTimeOffset.UtcNow;
                    return true;
                }
                return false;
            }

            public void Upsert(SessionState session)
                => _sessions[session.ClientId] = session;

            private async Task CleanupLoopAsync(CancellationToken ct)
            {
                while (!ct.IsCancellationRequested)
                {
                    var now = DateTimeOffset.UtcNow;
                    foreach (var (clientId, session) in _sessions)
                    {
                        if (now - session.LastSeen > _idleTimeout)
                        {
                            if (_sessions.TryRemove(clientId, out var removed))
                                removed.Dispose();
                        }
                    }
                    await Task.Delay(TimeSpan.FromSeconds(30), ct);
                }
            }

            public void Dispose()
            {
                _cts.Cancel();
                foreach (var kv in _sessions)
                    kv.Value.Dispose();
                _sessions.Clear();
            }
        }
    }
}
