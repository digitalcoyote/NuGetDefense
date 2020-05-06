using System;
using System.Linq;
using System.Xml;
using System.Xml.Linq;

namespace NuGetDefense
{
    public static class ExtensionMethods
    {
        public static XAttribute AttributeIgnoreCase(this XElement x, string name)
        {
            return x.Attributes()
                .FirstOrDefault(a => a.Name.ToString().Equals(name, StringComparison.OrdinalIgnoreCase));
        }
    }
}