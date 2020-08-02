using System;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace NuGetDefense.Configuration
{
    public class Settings
    {
        public bool WarnOnly { get; set; } = false;

        public FileLogSettings Log
        {
            get => Logs?.Length > 0 ? Logs[0] : null;
            set { Logs = new[] {value}; }
        }

        public FileLogSettings[] Logs { get; set; }
        public bool CheckTransitiveDependencies { get; set; } = true;

        public BuildErrorSettings ErrorSettings { get; set; } = new BuildErrorSettings();

        public VulnerabilitySourceConfiguration OssIndex { get; set; } = new VulnerabilitySourceConfiguration();

        public OfflineVulnerabilitySourceConfiguration NVD { get; set; } =
            new OfflineVulnerabilitySourceConfiguration();

        public static Settings LoadSettings(string directory)
        {
            Settings settings;

            try
            {
                if (File.Exists(Path.Combine(directory, "NuGetDefense.json")))
                {
                    var ops = new JsonSerializerOptions
                    {
                        IgnoreReadOnlyProperties = true,
                        PropertyNameCaseInsensitive = true,
                        ReadCommentHandling = JsonCommentHandling.Skip
                    };
                    settings = JsonSerializer.Deserialize<Settings>(
                        File.ReadAllText(Path.Combine(directory, "NuGetDefense.json")), ops);
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

            if (settings.ErrorSettings.BlacklistedPackages != null)
                settings.ErrorSettings.BlockedPackages =
                    settings.ErrorSettings.BlockedPackages.Concat(settings.ErrorSettings.BlacklistedPackages).ToArray();
            if (settings.ErrorSettings.WhiteListedPackages != null)
                settings.ErrorSettings.AllowedPackages =
                    settings.ErrorSettings.AllowedPackages.Concat(settings.ErrorSettings.WhiteListedPackages).ToArray();


            return settings;
        }

        public static void SaveSettings(Settings settings, string directory)
        {
            var ops = new JsonSerializerOptions
            {
                IgnoreReadOnlyProperties = true,
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                WriteIndented = true
            };
            File.WriteAllText(Path.Combine(directory, "NuGetDefense.json"),
                JsonSerializer.Serialize(settings, ops));
        }
    }
}