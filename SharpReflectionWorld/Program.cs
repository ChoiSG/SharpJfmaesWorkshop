using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharpReflectionWorld
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[SRW] Hello world from main function!");
        }

        public static void anotherFunction(string userInput)
        {
            Console.WriteLine("[SRW] Hello world from anotherFunction(), with userinput {0}", userInput);
        }

        // So, access class within a class like SharpReflectionWorld.Program.ProgramCat does not work
        public class ProgramCat
        {
            public static void meow()
            {
                Console.WriteLine("[SRW] meow");
            }
        }
    }

    public class Dog
    {
        public static void bark()
        {
            Console.WriteLine("[SRW] bark bark!");
        }
        public static void bork(string dogLang)
        {
            Console.WriteLine("[SRW] bork bork! {0}", dogLang);
        }
    }

    public class Cat
    {
        public static void meow()
        {
            Console.WriteLine("[SRW] meow");
        }
    }
}
