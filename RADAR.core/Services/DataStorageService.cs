using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
using RADAR.Core.Models;
using RADAR.Core.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

namespace RADAR.Core.Services
{
    public class DataStorageService
    {
        private readonly AppConfig _config;
        private readonly ILogger<DataStorageService> _logger;
        private readonly string _dataDirectory;
        private readonly JsonSerializerOptions _jsonOptions;

        public DataStorageService(AppConfig config, ILogger<DataStorageService> logger)
        {
            _config = config;
            _logger = logger;
            _dataDirectory = Path.Combine(_config.OutputDirectory, "Data");
            
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            EnsureDirectoryExists();
        }

        public async Task SaveAnalysisSessionAsync(ThreatIntelligenceReport report, List<ThreatIndicator> indicators, List<ThreatActor> actors)
        {
            try
            {
                var sessionId = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
                var sessionDir = Path.Combine(_dataDirectory, "Sessions", sessionId);
                Directory.CreateDirectory(sessionDir);

                _logger.LogInformation("Saving analysis session {SessionId}", sessionId);

                // Save main report
                var reportPath = Path.Combine(sessionDir, "analysis-report.json");
                var reportJson = JsonSerializer.Serialize(report, _jsonOptions);
                await File.WriteAllTextAsync(reportPath, reportJson);

                // Save indicators
                var indicatorsPath = Path.Combine(sessionDir, "indicators.json");
                var indicatorsJson = JsonSerializer.Serialize(indicators, _jsonOptions);
                await File.WriteAllTextAsync(indicatorsPath, indicatorsJson);

                // Save threat actors
                var actorsPath = Path.Combine(sessionDir, "threat-actors.json");
                var actorsJson = JsonSerializer.Serialize(actors, _jsonOptions);
                await File.WriteAllTextAsync(actorsPath, actorsJson);

                // Save session metadata
                var metadata = new
                {
                    SessionId = sessionId,
                    Timestamp = DateTime.UtcNow,
                    TotalIndicators = indicators.Count,
                    TotalActors = actors.Count,
                    ProcessingTimeMs = report.ProcessingTimeMs,
                    Sources = indicators.GroupBy(i => i.Source).ToDictionary(g => g.Key, g => g.Count())
                };

                var metadataPath = Path.Combine(sessionDir, "session-metadata.json");
                var metadataJson = JsonSerializer.Serialize(metadata, _jsonOptions);
                await File.WriteAllTextAsync(metadataPath, metadataJson);

                _logger.LogInformation("Analysis session {SessionId} saved successfully", sessionId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving analysis session");
                throw;
            }
        }

        public async Task<List<ThreatIndicator>> LoadHistoricalIndicatorsAsync(int maxSessions = 10)
        {
            var allIndicators = new List<ThreatIndicator>();

            try
            {
                var sessionsDir = Path.Combine(_dataDirectory, "Sessions");
                if (!Directory.Exists(sessionsDir))
                    return allIndicators;

                var sessionDirs = Directory.GetDirectories(sessionsDir)
                    .OrderByDescending(d => d)
                    .Take(maxSessions);

                foreach (var sessionDir in sessionDirs)
                {
                    var indicatorsPath = Path.Combine(sessionDir, "indicators.json");
                    if (File.Exists(indicatorsPath))
                    {
                        var json = await File.ReadAllTextAsync(indicatorsPath);
                        var indicators = JsonSerializer.Deserialize<List<ThreatIndicator>>(json, _jsonOptions);
                        if (indicators != null)
                        {
                            allIndicators.AddRange(indicators);
                        }
                    }
                }

                _logger.LogInformation("Loaded {Count} historical indicators from {Sessions} sessions", 
                    allIndicators.Count, sessionDirs.Count());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading historical indicators");
            }

            return allIndicators;
        }

        public async Task SaveThreatIntelligenceFeedAsync(string sourceName, DateTime timestamp, object data)
        {
            try
            {
                var feedDir = Path.Combine(_dataDirectory, "Feeds", sourceName);
                Directory.CreateDirectory(feedDir);

                var fileName = $"{timestamp:yyyyMMdd-HHmmss}.json";
                var filePath = Path.Combine(feedDir, fileName);

                var json = JsonSerializer.Serialize(data, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json);

                _logger.LogDebug("Saved raw feed data from {Source} to {FilePath}", sourceName, filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error saving threat intelligence feed data for {Source}", sourceName);
            }
        }

        public async Task<Dictionary<string, object>> GetAnalyticsDataAsync()
        {
            var analytics = new Dictionary<string, object>();

            try
            {
                var sessionsDir = Path.Combine(_dataDirectory, "Sessions");
                if (!Directory.Exists(sessionsDir))
                    return analytics;

                var sessionDirs = Directory.GetDirectories(sessionsDir);
                var sessionMetadata = new List<object>();

                foreach (var sessionDir in sessionDirs.OrderByDescending(d => d))
                {
                    var metadataPath = Path.Combine(sessionDir, "session-metadata.json");
                    if (File.Exists(metadataPath))
                    {
                        var json = await File.ReadAllTextAsync(metadataPath);
                        var metadata = JsonSerializer.Deserialize<object>(json);
                        if (metadata != null)
                        {
                            sessionMetadata.Add(metadata);
                        }
                    }
                }

                analytics["TotalSessions"] = sessionDirs.Length;
                analytics["SessionHistory"] = sessionMetadata;
                analytics["LastAnalysis"] = sessionDirs.Length > 0 ? Path.GetFileName(sessionDirs.OrderByDescending(d => d).First()) : null;
                analytics["DataDirectorySize"] = CalculateDirectorySize(_dataDirectory);
                analytics["AvailableSessions"] = sessionDirs.Select(Path.GetFileName).OrderByDescending(s => s).Take(20).ToList();

                _logger.LogInformation("Generated analytics data for {Sessions} sessions", sessionDirs.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating analytics data");
            }

            return analytics;
        }

        public async Task CleanupOldDataAsync(int maxSessions = 100, int maxDays = 30)
        {
            try
            {
                var sessionsDir = Path.Combine(_dataDirectory, "Sessions");
                if (!Directory.Exists(sessionsDir))
                    return;

                var sessionDirs = Directory.GetDirectories(sessionsDir)
                    .Select(d => new { Path = d, Name = Path.GetFileName(d) })
                    .OrderByDescending(d => d.Name)
                    .ToList();

                var cutoffDate = DateTime.UtcNow.AddDays(-maxDays);
                var sessionsToDelete = sessionDirs.Skip(maxSessions).ToList();

                // Also delete sessions older than maxDays
                var oldSessions = sessionDirs.Where(d => 
                    DateTime.TryParseExact(d.Name, "yyyyMMdd-HHmmss", null, System.Globalization.DateTimeStyles.None, out var sessionDate) &&
                    sessionDate < cutoffDate).ToList();

                sessionsToDelete.AddRange(oldSessions);
                sessionsToDelete = sessionsToDelete.Distinct().ToList();

                foreach (var session in sessionsToDelete)
                {
                    Directory.Delete(session.Path, true);
                    _logger.LogInformation("Deleted old session: {Session}", session.Name);
                }

                if (sessionsToDelete.Any())
                {
                    _logger.LogInformation("Cleanup completed: removed {Count} old sessions", sessionsToDelete.Count);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during data cleanup");
            }

            await Task.CompletedTask;
        }

        private void EnsureDirectoryExists()
        {
            try
            {
                Directory.CreateDirectory(_dataDirectory);
                Directory.CreateDirectory(Path.Combine(_dataDirectory, "Sessions"));
                Directory.CreateDirectory(Path.Combine(_dataDirectory, "Feeds"));
                Directory.CreateDirectory(_config.OutputDirectory);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating data directories");
                throw;
            }
        }

        private long CalculateDirectorySize(string directoryPath)
        {
            try
            {
                if (!Directory.Exists(directoryPath))
                    return 0;

                return Directory.GetFiles(directoryPath, "*", SearchOption.AllDirectories)
                    .Sum(file => new FileInfo(file).Length);
            }
            catch
            {
                return 0;
            }
        }
    }
}