using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using NuGetDefense.Core;

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
                Console.WriteLine(MsBuild.Log(Path.Combine(directory, "NuGetDefense.json"), MsBuild.Category.Error,
                    $"NuGetDefense Settings failed to load. Default Settings were used instead. Exception: {e}"));
                settings = new Settings();
            }

#pragma warning disable 618
            if (settings.ErrorSettings.BlacklistedPackages != null)
                settings.ErrorSettings.BlockedPackages =
                    settings.ErrorSettings.BlockedPackages.Concat(settings.ErrorSettings.BlacklistedPackages).ToArray();
            if (settings.ErrorSettings.WhiteListedPackages != null)
                settings.ErrorSettings.AllowedPackages =
                    settings.ErrorSettings.AllowedPackages.Concat(settings.ErrorSettings.WhiteListedPackages).ToArray();
#pragma warning restore 618


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