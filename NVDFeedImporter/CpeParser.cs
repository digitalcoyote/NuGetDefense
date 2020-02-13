namespace NVDFeedImporter
{
    public class Cpe
    {
        public string CpeVersion { get; set; }
        public string Vendor { get; set; }
        public string Part { get; set; }
        public string Product { get; set; }
        public string Update { get; set; }
        public string ProductVersion { get; set; }
        public string Language { get; set; }
        public string Edition { get; set; }
        public string TargetHardware { get; set; }
        public string SoftwareEdition { get; set; }
        public string Other { get; set; }

        /// <summary>
        ///     Parses a CPE string with the following format
        ///     cpe:2.3:(part):(vendor):(product):(version):(update):(edition):(language):(swEdition):(targetHw):(other)
        /// </summary>
        /// <param name="cpeString"></param>
        /// <returns></returns>
        public static Cpe Parse(string cpeString)
        {
            if (string.IsNullOrWhiteSpace(cpeString)) return null;
            // All we really care about is product and version (maybe vendor) of CPE's with "part" a (application)
            var cpeParts = cpeString.Split(':');

            return new Cpe
            {
                CpeVersion = cpeParts[1],
                Part = cpeParts[2],
                Vendor = cpeParts[3],
                Product = cpeParts[4],
                ProductVersion = cpeParts[5],
                Update = cpeParts[6],
                Edition = cpeParts[7],
                Language = cpeParts[8],
                SoftwareEdition = cpeParts[9],
                TargetHardware = cpeParts[10],
                Other = cpeParts[11]
            };
        }
    }
}