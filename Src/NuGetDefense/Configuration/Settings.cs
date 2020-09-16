using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading;
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

        public VulnerabilityReportsSettings VulnerabilityReports { get; set; } = new VulnerabilityReportsSettings();

        public FileLogSettings[] Logs { get; set; }
        public bool CheckTransitiveDependencies { get; set; } = true;

        public BuildErrorSettings ErrorSettings { get; set; } = new BuildErrorSettings();

        public VulnerabilitySourceConfiguration OssIndex { get; set; } = new VulnerabilitySourceConfiguration();

        public OfflineVulnerabilitySourceConfiguration NVD { get; set; } =
            new OfflineVulnerabilitySourceConfiguration();

        public static Settings LoadSettings(string directory)
        {
            Settings settings;

            var settingsFilePath = Path.Combine(directory, "NuGetDefense.json");
            try
            {
                //Edit to allow it to repeatedly check if hte file exists prior to multiple instances trying to save over it.
                if (File.Exists(settingsFilePath))
                {
                    settings = LoadSettingsFile(settingsFilePath);
                }
                else
                {
                    settings = new Settings();
                    SpinWait.SpinUntil(() =>
                    {
                        try
                        {
                            if (SaveSettings(settings, settingsFilePath)) return true;
                            settings = LoadSettingsFile(settingsFilePath);

                            return true;
                        }
                        catch
                        {
                            return false;
                        }
                    }, TimeSpan.FromMinutes(5));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(MsBuild.Log(settingsFilePath, MsBuild.Category.Error,
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

        private static Settings LoadSettingsFile(string settingsFilePath)
        {
            Settings settings;
            var settingsFileContents = ReadSettingsFileWhenAble(settingsFilePath, TimeSpan.FromMinutes(5));

            var ops = new JsonSerializerOptions
            {
                IgnoreReadOnlyProperties = true,
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                IgnoreNullValues = true,
                AllowTrailingCommas = true,
            };
            
            settings = JsonSerializer.Deserialize<Settings>(settingsFileContents, ops);
            return settings;
        }

        private static string ReadSettingsFileWhenAble(string settingsFile, TimeSpan timeout)
        {
            var settingsFileContents = string.Empty;
            SpinWait.SpinUntil(() =>
            {
                try
                {
                    using Stream settingsStream = File.Open(settingsFile, FileMode.Open, FileAccess.Read, FileShare.Read);
                    using var settingsReader = new StreamReader(settingsStream);
                    settingsFileContents = settingsReader.ReadToEnd();
                    return true;
                }
                catch
                {
                    return false;
                }
            }, timeout);

            return settingsFileContents;
        }

        private static bool SaveSettings(Settings settings, string settingsFilePath)
        {
            var ops = new JsonSerializerOptions
            {
                IgnoreReadOnlyProperties = true,
                PropertyNameCaseInsensitive = true,
                ReadCommentHandling = JsonCommentHandling.Skip,
                IgnoreNullValues = true,
                AllowTrailingCommas = true,
                WriteIndented = true,
            };

            try
            {
                File.WriteAllText(settingsFilePath,
                    JsonSerializer.Serialize(settings, ops));
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}