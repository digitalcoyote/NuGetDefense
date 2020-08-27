using Serilog;
using Serilog.Events;

namespace NuGetDefense.Configuration
{
    public class FileLogSettings
    {
        public enum LogFormat
        {
            Standard,
            JSON,
            XML
        }

        public string OutPut { get; set; } = "{project}.NuGetDefense.log";
        public LogEventLevel LogLevel { get; set; } = LogEventLevel.Information;
        public RollingInterval RollingInterval { get; set; } = RollingInterval.Infinite;

        public LogFormat Format { get; set; } = LogFormat.Standard;
    }
}