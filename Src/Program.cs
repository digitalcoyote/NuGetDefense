using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace NuGetDefense
{
    class Program
    {
        static void Main(string[] args)
        {
           
        }
        
        
        /// <summary>
        /// Loads NuGet packages in use form packages.config or PackageReferences in the project file
        /// </summary>
        /// <returns></returns>
        public static IEnumerable<NuGetPackage> LoadPackages()
        {
            if(File.Exists("packages.config"))
            {
                return XElement.Load("package.config").DescendantsAndSelf("Package").Select(x => new NuGetPackage()
                    {Id = x.Attribute("id").Value, Version = x.Attribute("Version").Value});
            }
            else
            {
                return XElement.Load("ProjectFileHere").DescendantsAndSelf("PackageReference").Select(x => new NuGetPackage()
                    {Id = x.Attribute("Include").Value, Version = x.Attribute("Version").Value});
            }
        }
    }
}