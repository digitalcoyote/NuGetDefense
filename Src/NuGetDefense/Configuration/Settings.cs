using System;
using System.IO;
using System.Text.Json;

namespace NuGetDefense.Configuration
{
    public class Settings
    {
        public bool WarnOnly { get; set; } = false;

        public BuildErrorSettings ErrorSettings { get; set; } = new BuildErrorSettings();

        public VulnerabilitySourceConfiguration OssIndex { get; set; } = new VulnerabilitySourceConfiguration();

        public OfflineVulnerabilitySourceConfiguration NVD { get; set; } =
            new OfflineVulnerabilitySourceConfiguration();

        internal static Settings LoadSettings(string directory)
        {
            Settings settings;

            try
            {
                if (File.Exists(Path.Combine(directory, "NuGetDefense.json")))
                {
                    settings = JsonSerializer.Deserialize<Settings>(
                        File.ReadAllText(Path.Combine(directory, "NuGetDefense.json")));
                }
                else
                {
                    settings = new Settings();
                    SaveSettings(settings, directory);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(
                    $"{Path.Combine(directory, "NuGetDefense.json")} : Error : NuGetDefense Settings failed to load. Default Settings were used instead. Exception: {e}");
                settings = new Settings();
            }

            return settings;
        }

        public static void SaveSettings(Settings settings, string directory)
        {
            File.WriteAllText(Path.Combine(directory, "NuGetDefense.json"),
                JsonSerializer.Serialize(settings, new JsonSerializerOptions {WriteIndented = true}));
        }
    }
}