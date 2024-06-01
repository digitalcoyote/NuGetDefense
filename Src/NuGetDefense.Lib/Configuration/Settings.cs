using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using NuGetDefense.Core;

namespace NuGetDefense.Configuration;

public class Settings
{
    public bool WarnOnly { get; set; }

    public FileLogSettings? Log
    {
        get => Logs?.Length > 0 ? Logs[0] : null;
        set { Logs = [value]; }
    }

    public VulnerabilityReportsSettings VulnerabilityReports { get; set; } = new();

    public FileLogSettings[]? Logs { get; set; }
    public bool CheckTransitiveDependencies { get; set; } = true;
    public bool CheckReferencedProjects { get; set; }

    public BuildErrorSettings ErrorSettings { get; set; } = new();

    public RemoteVulnerabilitySourceConfiguration OssIndex { get; set; } = new();
    public RemoteVulnerabilitySourceConfiguration GitHubAdvisoryDatabase { get; set; } = new() { BreakIfCannotRun = false };
    public string? CacheLocation { get; set; }

    public OfflineVulnerabilitySourceConfiguration NVD { get; set; } =
        new();

    public RemoteVulnerabilitySourceConfiguration NvdApi { get; set; } = new();

    public string[] SensitivePackages { get; set; } = [];

    public static Settings LoadSettings(string? settingsFilePath = "")
    {
        if (string.IsNullOrWhiteSpace(settingsFilePath))
        {
            settingsFilePath = Scanner.GlobalConfigFile;
        }
        
        Settings settings;

        try
        {
            // Edit to allow it to repeatedly check if the file exists prior to multiple instances trying to save over it.
            settings = File.Exists(settingsFilePath) ? LoadSettingsFile(settingsFilePath) : CreateDefaultSettingsFile(settingsFilePath);
        }
        catch (Exception e)
        {
            Console.WriteLine(MsBuild.Log(settingsFilePath, MsBuild.Category.Warning,
                $"NuGetDefense Settings failed to load. Default Settings were used instead. Exception: {e}"));
            settings = new();
        }

#pragma warning disable 618
        if (settings.ErrorSettings.BlacklistedPackages != null)
            settings.ErrorSettings.BlockedPackages =
                settings.ErrorSettings.BlockedPackages?.Concat(settings.ErrorSettings.BlacklistedPackages).ToArray();
        if (settings.ErrorSettings.WhiteListedPackages != null)
            settings.ErrorSettings.AllowedPackages =
                settings.ErrorSettings.AllowedPackages?.Concat(settings.ErrorSettings.WhiteListedPackages).ToArray();
#pragma warning restore 618

        return settings;
    }

    public static Settings CreateDefaultSettingsFile(string settingsFilePath)
    {
        var defaultSettings = new Settings();
        SpinWait.SpinUntil(() =>
        {
            try
            {
                if (SaveSettings(defaultSettings, settingsFilePath)) return true;
                // Assume it failed to save because the file exists and try to load it
                defaultSettings = LoadSettingsFile(settingsFilePath);

                return true;
            }
            catch
            {
                return false;
            }
        }, TimeSpan.FromMinutes(5));
        return defaultSettings;
    }

    public static Settings LoadSettingsFile(string settingsFilePath)
    {
        var settingsFileContents = ReadSettingsFileWhenAble(settingsFilePath, TimeSpan.FromMinutes(5));

        var ops = new JsonSerializerOptions
        {
            IgnoreReadOnlyProperties = true,
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
        };

        var settings = JsonSerializer.Deserialize<Settings>(settingsFileContents, ops)!;
        return settings;
    }

    private static string ReadSettingsFileWhenAble(string settingsFile, TimeSpan timeout)
    {
        var settingsFileContents = string.Empty;

        if (File.Exists(settingsFile))
            SpinWait.SpinUntil(() =>
            {
                try
                {
                    using Stream settingsStream =
                        File.Open(settingsFile, FileMode.Open, FileAccess.Read, FileShare.Read);
                    using var settingsReader = new StreamReader(settingsStream);
                    settingsFileContents = settingsReader.ReadToEnd();
                    return true;
                }
                catch
                {
                    return false;
                }
            }, timeout);
        else
            throw new FileNotFoundException("Settings file not Found!", settingsFile);

        return settingsFileContents;
    }

    private static bool SaveSettings(Settings settings, string settingsFilePath)
    {
        var ops = new JsonSerializerOptions
        {
            IgnoreReadOnlyProperties = true,
            PropertyNameCaseInsensitive = true,
            ReadCommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true,
            WriteIndented = true,
            Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
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