using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
using RADAR.Core.Interfaces;
using RADAR.Core.Models;
using RADAR.Core.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace RADAR.Core.Services
{
    public class ReportGenerator : IReportGenerator
    {
        private readonly AppConfig _config;
        private readonly ILogger<ReportGenerator> _logger;
        private readonly JsonSerializerOptions _jsonOptions;

        public ReportGenerator(AppConfig config, ILogger<ReportGenerator> logger)
        {
            _config = config;
            _logger = logger;
            _jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };
        }

        public async Task GenerateJsonReportAsync(List<CorrelationResult> correlations, string filePath)
        {
            try
            {
                _logger.LogInformation("Generating JSON correlation report to {FilePath}", filePath);
                
                var reportData = new
                {
                    GeneratedAt = DateTime.UtcNow,
                    TotalCorrelations = correlations.Count,
                    CorrelationTypes = correlations.GroupBy(c => c.CorrelationType).ToDictionary(g => g.Key, g => g.Count()),
                    HighConfidenceCount = correlations.Count(c => c.ConfidenceScore >= _config.Correlation.MinimumConfidenceThreshold),
                    Correlations = correlations.Select(c => new
                    {
                        c.Id,
                        c.CorrelationType,
                        c.Description,
                        c.ConfidenceScore,
                        c.DiscoveredAt,
                        IndicatorCount = c.RelatedIndicators.Count,
                        Sources = c.RelatedIndicators.Select(i => i.Source).Distinct().ToList(),
                        c.AnalysisDetails
                    })
                };

                var json = JsonSerializer.Serialize(reportData, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json);
                
                _logger.LogInformation("JSON report generated successfully with {Count} correlations", correlations.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating JSON report");
                throw;
            }
        }

        public async Task GenerateCsvReportAsync(List<ThreatIndicator> indicators, string filePath)
        {
            try
            {
                _logger.LogInformation("Generating CSV indicators report to {FilePath}", filePath);
                
                var csv = new StringBuilder();
                
                // CSV Header
                csv.AppendLine("Timestamp,Type,Value,Source,Confidence,ThreatActor,MalwareFamily,Tags,Description");
                
                // CSV Data
                foreach (var indicator in indicators.OrderByDescending(i => i.Confidence))
                {
                    var tags = string.Join("|", indicator.Tags ?? new List<string>());
                    var description = EscapeCsvField(indicator.Description ?? "");
                    var threatActor = EscapeCsvField(indicator.ThreatActor ?? "");
                    var malwareFamily = EscapeCsvField(indicator.MalwareFamily ?? "");
                    
                    csv.AppendLine($"{indicator.Created:yyyy-MM-dd HH:mm:ss},{indicator.Type},{EscapeCsvField(indicator.Value)},{indicator.Source},{indicator.Confidence},{threatActor},{malwareFamily},{tags},{description}");
                }

                await File.WriteAllTextAsync(filePath, csv.ToString());
                
                _logger.LogInformation("CSV report generated successfully with {Count} indicators", indicators.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating CSV report");
                throw;
            }
        }

        public async Task GenerateThreatActorReportAsync(List<ThreatActor> actors, string filePath)
        {
            try
            {
                _logger.LogInformation("Generating threat actor report to {FilePath}", filePath);
                
                var reportData = new
                {
                    GeneratedAt = DateTime.UtcNow,
                    TotalActors = actors.Count,
                    TotalIndicators = actors.Sum(a => a.Indicators.Count),
                    TotalTTPs = actors.Sum(a => a.TTPs.Count),
                    ActorsByCountry = actors.Where(a => !string.IsNullOrEmpty(a.Country))
                                           .GroupBy(a => a.Country!)
                                           .ToDictionary(g => g.Key, g => g.Count()),
                    ThreatActors = actors.OrderByDescending(a => a.Indicators.Count).Select(a => new
                    {
                        a.Name,
                        a.Aliases,
                        a.Country,
                        a.Motivation,
                        a.Targets,
                        a.TTPs,
                        a.FirstSeen,
                        a.LastActivity,
                        IndicatorCount = a.Indicators.Count,
                        UniqueIndicatorTypes = a.Indicators.GroupBy(i => i.Type).ToDictionary(g => g.Key.ToString(), g => g.Count()),
                        MalwareFamilies = a.Indicators.Where(i => !string.IsNullOrEmpty(i.MalwareFamily))
                                                     .Select(i => i.MalwareFamily!)
                                                     .Distinct()
                                                     .ToList()
                    })
                };

                var json = JsonSerializer.Serialize(reportData, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json);
                
                _logger.LogInformation("Threat actor report generated successfully with {Count} actors", actors.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating threat actor report");
                throw;
            }
        }

        public async Task GenerateExecutiveSummaryAsync(ThreatIntelligenceReport report, string filePath)
        {
            try
            {
                _logger.LogInformation("Generating executive summary to {FilePath}", filePath);
                
                var summary = new StringBuilder();
                
                summary.AppendLine("# RADAR Threat Intelligence Executive Summary");
                summary.AppendLine($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC");
                summary.AppendLine($"Processing Time: {report.ProcessingTimeMs:N0}ms");
                summary.AppendLine();
                
                summary.AppendLine("## Key Findings");
                summary.AppendLine($"- **{report.TotalIndicators:N0}** threat indicators processed");
                summary.AppendLine($"- **{report.TotalThreatActors:N0}** threat actors identified");
                summary.AppendLine($"- **{report.Correlations.Count:N0}** correlations discovered");
                summary.AppendLine($"- **{report.InfrastructurePivots.Count:N0}** infrastructure pivots detected");
                summary.AppendLine();

                if (report.IndicatorsBySource.Any())
                {
                    summary.AppendLine("## Intelligence Sources");
                    foreach (var kvp in report.IndicatorsBySource.OrderByDescending(x => x.Value))
                    {
                        summary.AppendLine($"- **{kvp.Key}**: {kvp.Value:N0} indicators");
                    }
                    summary.AppendLine();
                }

                if (report.TopMalwareFamilies.Any())
                {
                    summary.AppendLine("## Top Malware Families");
                    foreach (var kvp in report.TopMalwareFamilies.Take(10))
                    {
                        summary.AppendLine($"- **{kvp.Key}**: {kvp.Value:N0} samples");
                    }
                    summary.AppendLine();
                }

                if (report.HighConfidenceCorrelations.Any())
                {
                    summary.AppendLine("## High-Confidence Correlations");
                    foreach (var correlation in report.HighConfidenceCorrelations.Take(10))
                    {
                        summary.AppendLine($"- **{correlation.CorrelationType}**: {correlation.Description} ({correlation.ConfidenceScore:P1})");
                    }
                    summary.AppendLine();
                }

                if (report.InfrastructurePivots.Any())
                {
                    summary.AppendLine("## Infrastructure Pivots");
                    foreach (var pivot in report.InfrastructurePivots.Take(10))
                    {
                        summary.AppendLine($"- **{pivot.PivotType}**: {pivot.SharedInfrastructure.Value} shared by {pivot.ThreatActors.Count} actors ({pivot.ConfidenceScore:P1})");
                    }
                    summary.AppendLine();
                }

                summary.AppendLine("## Confidence Distribution");
                if (report.IndicatorsByConfidence.Any())
                {
                    foreach (var kvp in report.IndicatorsByConfidence)
                    {
                        summary.AppendLine($"- **{kvp.Key}**: {kvp.Value:N0} indicators");
                    }
                }

                await File.WriteAllTextAsync(filePath, summary.ToString());
                
                _logger.LogInformation("Executive summary generated successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating executive summary");
                throw;
            }
        }

        public async Task GenerateInfrastructurePivotReportAsync(List<InfrastructurePivot> pivots, string filePath)
        {
            try
            {
                _logger.LogInformation("Generating infrastructure pivot report to {FilePath}", filePath);
                
                var reportData = new
                {
                    GeneratedAt = DateTime.UtcNow,
                    TotalPivots = pivots.Count,
                    PivotTypes = pivots.GroupBy(p => p.PivotType).ToDictionary(g => g.Key, g => g.Count()),
                    HighConfidencePivots = pivots.Count(p => p.ConfidenceScore >= 0.8),
                    InfrastructurePivots = pivots.OrderByDescending(p => p.ConfidenceScore).Select(p => new
                    {
                        p.Id,
                        p.PivotType,
                        p.ConfidenceScore,
                        p.DiscoveredAt,
                        SharedInfrastructure = new
                        {
                            p.SharedInfrastructure.Value,
                            p.SharedInfrastructure.Type,
                            p.SharedInfrastructure.Source
                        },
                        p.ThreatActors,
                        p.Evidence,
                        p.RelatedCampaigns
                    })
                };

                var json = JsonSerializer.Serialize(reportData, _jsonOptions);
                await File.WriteAllTextAsync(filePath, json);
                
                _logger.LogInformation("Infrastructure pivot report generated with {Count} pivots", pivots.Count);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating infrastructure pivot report");
                throw;
            }
        }

        private string EscapeCsvField(string field)
        {
            if (string.IsNullOrEmpty(field))
                return "";
            
            if (field.Contains(',') || field.Contains('"') || field.Contains('\n'))
            {
                return $"\"{field.Replace("\"", "\"\"")}\"";
            }
            
            return field;
        }
    }
}