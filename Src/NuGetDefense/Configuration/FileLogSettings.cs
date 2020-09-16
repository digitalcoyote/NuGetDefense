using Serilog;
using Serilog.Events;

namespace NuGetDefense.Configuration
{
    public class FileLogSettings
    {
        public string OutPut { get; set; } = "{project}.NuGetDefense.log";
        public LogEventLevel LogLevel { get; set; } = LogEventLevel.Information;
        public RollingInterval RollingInterval { get; set; } = RollingInterval.Infinite;
    }
}