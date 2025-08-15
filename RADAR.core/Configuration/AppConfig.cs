using System;
using System.Collections.Generic;

namespace RADAR.Core.Configuration
{
    public class AppConfig
    {
        public List<ThreatFeedConfig> ThreatFeeds { get; set; } = new List<ThreatFeedConfig>();
        public string? DatabaseConnectionString { get; set; }
        public int MaxConcurrentRequests { get; set; } = 5;
        public TimeSpan RequestTimeout { get; set; } = TimeSpan.FromSeconds(30);
        public string LogLevel { get; set; } = "Information";
        public CorrelationSettings Correlation { get; set; } = new CorrelationSettings();
        public string OutputDirectory { get; set; } = "./Reports";
    }

    public class ThreatFeedConfig
    {
        public string Name { get; set; } = string.Empty;
        public string BaseUrl { get; set; } = string.Empty;
        public string ApiKey { get; set; } = string.Empty;
        public TimeSpan RefreshInterval { get; set; } = TimeSpan.FromHours(1);
        public bool IsActive { get; set; } = true;
        public Dictionary<string, string> Headers { get; set; } = new Dictionary<string, string>();
        public int RateLimitPerMinute { get; set; } = 60;
    }

    public class CorrelationSettings
    {
        public double MinimumConfidenceThreshold { get; set; } = 0.7;
        public int MaxIndicatorsPerCorrelation { get; set; } = 1000;
        public bool EnableInfrastructurePivots { get; set; } = true;
        public List<string> IgnoredDomains { get; set; } = new List<string> 
        { 
            "google.com", 
            "microsoft.com", 
            "cloudflare.com",
            "amazonaws.com" 
        };
    }
}