using System.Runtime.Serialization;
using MagicOnion;
using MessagePack;

namespace EclipseLCL
{

    [DataContract]
    public class DiracRequest
    {
        [DataMember] public string FunctionName; //The function we wish to call within this app
        [DataMember] public Dictionary<string, object> Parameters; //The parameters for the function,  handled with PackData

        public DiracRequest(string functionName, Dictionary<string, object?> parameters)
        {
            FunctionName = functionName;
            Parameters = parameters;
        }

    }

    [MessagePackObject(keyAsPropertyName: true)]
    [DataContract]
    public class DiracResponse
    {
        [DataMember] public bool Success { get; set; }  //Did this work?
        [DataMember] public byte[] EncryptedData { get; set; } //The data returned from the function, handled with UnpackData
        [DataMember] public string ServerMessage { get; set; } //Information about the run

        public DiracResponse(bool success, byte[] encryptedData, string serverMessage)
        {
            Success = success;
            EncryptedData = encryptedData;
            ServerMessage = serverMessage;
        }
    }

}


