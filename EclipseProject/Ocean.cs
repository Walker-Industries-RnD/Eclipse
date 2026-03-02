using EclipseLCL;
using MagicOnion;
using MessagePack;
using Pariah_Cybersecurity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using WISecureData;
using static EclipseProject.Security;
using static Pariah_Cybersecurity.DataHandler;

namespace EclipseProject
{
    public class Ocean
    {

        public class RegisteredFunction
        {
            public Type DeclaringType { get; set; }
            public MethodInfo Method { get; set; }

            internal RegisteredFunction(Type declaringType, MethodInfo method)
            {
                DeclaringType = declaringType;
                Method = method;
            }
        }


        //All our registered functions
        internal Dictionary<string, RegisteredFunction> Ark = new();

        //We will only flood blessed land, so we will only register functions with the SeaOfDirac attribute
        private System.Reflection.Assembly assembly = Assembly.GetExecutingAssembly();

        //Add all the functions to the sea; let these souls be free to roam the sea and be used by other applications
        public void FloodTheSea()
        {
            foreach (var type in assembly.GetTypes())
            {
                foreach (var method in type.GetMethods())
                {
                    var attr = method.GetCustomAttribute<SeaOfDirac>();
                    if (attr != null)
                    {
                        Ark.Add(attr.Name, new RegisteredFunction(type, method));
                    }
                }
            }

        }


        //This function will be called by the ATField; it will handle the logic
        //of calling the correct function and returning the data to the ATField, which will then return it to the caller

        private SecureData EncKey;

        public async Task<DiracResponse> HandleRequestAsync(DiracRequest request, AeadChannel channel)
        {
            if (!Ark.TryGetValue(request.FunctionName, out var regFunc))
                return new DiracResponse(false, Array.Empty<byte>(), "Function not found in Eclipse Ocean");

            try
            {
                // Get the SeaOfDirac attribute
                var attr = regFunc.Method.GetCustomAttribute<SeaOfDirac>();
                if (attr == null)
                    throw new Exception("Registered function missing SeaOfDirac attribute");

                // Parameter count check
                if (attr.ParameterTypes.Length != request.Parameters.Count)
                    throw new Exception("Parameter count mismatch");

                // Unpack parameters using attribute types
                object?[] args = new object?[attr.ParameterTypes.Length];
                int i = 0;
                foreach (var kv in request.Parameters)
                {
                    if (kv.Value == null)
                    {
                        args[i++] = null;
                        continue;
                    }

                    Console.WriteLine($"PARAM: {kv.Key} : {kv.Value}");
                    args[i++] = kv.Value;
                }

                // Handle static vs instance
                object? instance = regFunc.Method.IsStatic ? null : Activator.CreateInstance(regFunc.DeclaringType);

                // Invoke the method
                var result = regFunc.Method.Invoke(instance, args);
                
                byte[] serializedResult = MessagePackSerializer.Serialize<object?>(result);
                var env = channel.Encrypt(request.FunctionName, serializedResult);

                byte[] serializedEnv = MessagePackSerializer.Serialize(env);

                return new DiracResponse(true, serializedEnv, "Success");
            }
            catch (Exception ex)
            {
                return new DiracResponse(false, Array.Empty<byte>(), ex.Message);
            }
        }




        //Let the third impact begin.

        //Launch the server; this will allow other applications to call our functions


        public class FunctionParameter
        {
            public string Name { get; set; } = "";
            public string Type { get; set; } = "";
        }


        //List all the functions 
        public IEnumerable<object> ListFunctionDetails()
        {
            return Ark.Select(kvp =>
            {
                var attr = kvp.Value.Method.GetCustomAttribute<SeaOfDirac>();

                var parameters = new List<FunctionParameter>();
                if (attr != null)
                {
                    for (int i = 0; i < attr.ParameterTypes.Length; i++)
                    {
                        parameters.Add(new FunctionParameter
                        {
                            Name = attr.ParameterNames?[i] ?? $"param{i}",
                            Type = attr.ParameterTypes[i].Name
                        });
                    }
                }

                return new
                {
                    Name = kvp.Key,
                    Parameters = parameters,
                    ReturnType = attr?.ReturnType.Name
                };
            });
        }



    }
}
