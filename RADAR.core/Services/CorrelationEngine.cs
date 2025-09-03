using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
using RADAR.Core.Interfaces;
using RADAR.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RADAR.Core.Services
{
    public class CorrelationEngine : ICorrelationEngine
    {
        private readonly AppConfig _config;
        private readonly ILogger<CorrelationEngine> _logger;

        public CorrelationEngine(AppConfig config, ILogger<CorrelationEngine> logger)
        {
            _config = config;
            _logger = logger;
        }

        public async Task<List<CorrelationResult>> FindCorrelationsAsync(List<ThreatIndicator> indicators)
        {
            var correlations = new List<CorrelationResult>();

            try
            {
                _logger.LogInformation("Starting correlation analysis on {Count} indicators", indicators.Count);

                // Cross-source correlation: Find same indicators from different sources
                var crossSourceCorrelations = await FindCrossSourceCorrelationsAsync(indicators);
                correlations.AddRange(crossSourceCorrelations);

                // Temporal correlation: Find indicators appearing around the same time
                var temporalCorrelations = await FindTemporalCorrelationsAsync(indicators);
                correlations.AddRange(temporalCorrelations);

                // Threat actor correlation: Group indicators by threat actor
                var actorCorrelations = await FindThreatActorCorrelationsAsync(indicators);
                correlations.AddRange(actorCorrelations);

                // Malware family correlation: Group indicators by malware family
                var familyCorrelations = await FindMalwareFamilyCorrelationsAsync(indicators);
                correlations.AddRange(familyCorrelations);

                // Infrastructure pattern correlation: Find related domains/IPs
                var infrastructureCorrelations = await FindInfrastructureCorrelationsAsync(indicators);
                correlations.AddRange(infrastructureCorrelations);

                _logger.LogInformation("Found {Count} correlations across all analysis types", correlations.Count);
                return correlations.OrderByDescending(c => c.ConfidenceScore).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during correlation analysis");
                return correlations;
            }
        }

        public async Task<List<InfrastructurePivot>> FindInfrastructurePivotsAsync(List<ThreatIndicator> indicators)
        {
            var pivots = new List<InfrastructurePivot>();

            try
            {
                _logger.LogInformation("Starting infrastructure pivot analysis");

                // Group infrastructure indicators by value to find shared usage
                var infraGroups = indicators
                    .Where(i => i.Type == IndicatorType.IpAddress || i.Type == IndicatorType.Domain)
                    .GroupBy(i => i.Value.ToLowerInvariant())
                    .Where(g => g.Count() > 1); // Infrastructure used by multiple sources

                foreach (var group in infraGroups)
                {
                    var sharedIndicators = group.ToList();
                    var uniqueActors = sharedIndicators
                        .Select(i => i.ThreatActor)
                        .Where(a => !string.IsNullOrEmpty(a))
                        .Distinct()
                        .ToList();

                    var uniqueSources = sharedIndicators
                        .Select(i => i.Source)
                        .Distinct()
                        .ToList();

                    if (uniqueActors.Count > 1 || uniqueSources.Count > 1)
                    {
                        var pivot = new InfrastructurePivot
                        {
                            ThreatActors = uniqueActors,
                            SharedInfrastructure = sharedIndicators.First(),
                            PivotType = DeterminePivotType(sharedIndicators.First()),
                            ConfidenceScore = CalculatePivotConfidence(sharedIndicators, uniqueActors, uniqueSources),
                            Evidence = CreatePivotEvidence(sharedIndicators, uniqueActors, uniqueSources)
                        };

                        pivots.Add(pivot);
                    }
                }

                _logger.LogInformation("Found {Count} infrastructure pivots", pivots.Count);
                return pivots.OrderByDescending(p => p.ConfidenceScore).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during infrastructure pivot analysis");
                return pivots;
            }
        }

        public async Task<List<ThreatIndicator>> FindRelatedIndicatorsAsync(ThreatIndicator indicator)
        {
            var related = new List<ThreatIndicator>();

            // This would typically query a database or cache of previously collected indicators
            // For now, return empty list as this requires persistent storage
            await Task.CompletedTask;

            return related;
        }

        private async Task<List<CorrelationResult>> FindCrossSourceCorrelationsAsync(List<ThreatIndicator> indicators)
        {
            var correlations = new List<CorrelationResult>();

            // Group indicators by value to find same IOCs from different sources
            var crossSourceGroups = indicators
                .GroupBy(i => i.Value.ToLowerInvariant())
                .Where(g => g.Select(i => i.Source).Distinct().Count() > 1);

            foreach (var group in crossSourceGroups.Take(50)) // Limit for performance
            {
                var relatedIndicators = group.ToList();
                var sources = relatedIndicators.Select(i => i.Source).Distinct().ToList();

                var correlation = new CorrelationResult
                {
                    RelatedIndicators = relatedIndicators,
                    CorrelationType = "CROSS_SOURCE_VALIDATION",
                    ConfidenceScore = CalculateCrossSourceConfidence(sources.Count),
                    Description = $"IOC {group.Key} confirmed by {sources.Count} independent sources",
                    AnalysisDetails = new Dictionary<string, object>
                    {
                        ["sources"] = sources,
                        ["validation_count"] = sources.Count
                    }
                };

                correlations.Add(correlation);
            }

            await Task.CompletedTask;
            return correlations;
        }

        private async Task<List<CorrelationResult>> FindTemporalCorrelationsAsync(List<ThreatIndicator> indicators)
        {
            var correlations = new List<CorrelationResult>();

            // Group indicators by time windows (e.g., same hour/day)
            var timeWindows = indicators
                .GroupBy(i => new { 
                    Date = i.Created.Date, 
                    Hour = i.Created.Hour 
                })
                .Where(g => g.Count() > 10); // Significant activity in time window

            foreach (var window in timeWindows.Take(20))
            {
                var windowIndicators = window.ToList();
                var uniqueSources = windowIndicators.Select(i => i.Source).Distinct().Count();

                if (uniqueSources > 1) // Multi-source temporal correlation
                {
                    var correlation = new CorrelationResult
                    {
                        RelatedIndicators = windowIndicators,
                        CorrelationType = "TEMPORAL_CLUSTER",
                        ConfidenceScore = CalculateTemporalConfidence(windowIndicators.Count, uniqueSources),
                        Description = $"Coordinated threat activity: {windowIndicators.Count} indicators from {uniqueSources} sources within 1-hour window",
                        AnalysisDetails = new Dictionary<string, object>
                        {
                            ["time_window"] = $"{window.Key.Date:yyyy-MM-dd} {window.Key.Hour:D2}:00",
                            ["indicator_count"] = windowIndicators.Count,
                            ["source_diversity"] = uniqueSources
                        }
                    };

                    correlations.Add(correlation);
                }
            }

            await Task.CompletedTask;
            return correlations;
        }

        private async Task<List<CorrelationResult>> FindThreatActorCorrelationsAsync(List<ThreatIndicator> indicators)
        {
            var correlations = new List<CorrelationResult>();

            // Group by threat actor
            var actorGroups = indicators
                .Where(i => !string.IsNullOrEmpty(i.ThreatActor))
                .GroupBy(i => i.ThreatActor!)
                .Where(g => g.Count() > 5);

            foreach (var group in actorGroups.Take(25))
            {
                var actorIndicators = group.ToList();
                var sources = actorIndicators.Select(i => i.Source).Distinct().ToList();

                var correlation = new CorrelationResult
                {
                    RelatedIndicators = actorIndicators,
                    CorrelationType = "THREAT_ACTOR_ATTRIBUTION",
                    ConfidenceScore = CalculateActorConfidence(actorIndicators.Count, sources.Count),
                    Description = $"Threat actor {group.Key} activities: {actorIndicators.Count} indicators across {sources.Count} intelligence sources",
                    AnalysisDetails = new Dictionary<string, object>
                    {
                        ["actor_name"] = group.Key,
                        ["indicator_types"] = actorIndicators.GroupBy(i => i.Type).ToDictionary(g => g.Key.ToString(), g => g.Count()),
                        ["source_attribution"] = sources
                    }
                };

                correlations.Add(correlation);
            }

            await Task.CompletedTask;
            return correlations;
        }

        private async Task<List<CorrelationResult>> FindMalwareFamilyCorrelationsAsync(List<ThreatIndicator> indicators)
        {
            var correlations = new List<CorrelationResult>();

            // Group by malware family
            var familyGroups = indicators
                .Where(i => !string.IsNullOrEmpty(i.MalwareFamily))
                .GroupBy(i => i.MalwareFamily!)
                .Where(g => g.Count() > 3);

            foreach (var group in familyGroups.Take(30))
            {
                var familyIndicators = group.ToList();
                var sources = familyIndicators.Select(i => i.Source).Distinct().ToList();

                var correlation = new CorrelationResult
                {
                    RelatedIndicators = familyIndicators,
                    CorrelationType = "MALWARE_FAMILY_CLUSTER",
                    ConfidenceScore = CalculateFamilyConfidence(familyIndicators.Count, sources.Count),
                    Description = $"Malware family {group.Key}: {familyIndicators.Count} related samples from {sources.Count} sources",
                    AnalysisDetails = new Dictionary<string, object>
                    {
                        ["malware_family"] = group.Key,
                        ["sample_count"] = familyIndicators.Count,
                        ["hash_types"] = familyIndicators.Where(i => i.Type == IndicatorType.FileHash).Count(),
                        ["source_diversity"] = sources.Count
                    }
                };

                correlations.Add(correlation);
            }

            await Task.CompletedTask;
            return correlations;
        }

        private async Task<List<CorrelationResult>> FindInfrastructureCorrelationsAsync(List<ThreatIndicator> indicators)
        {
            var correlations = new List<CorrelationResult>();

            // Look for domain/subdomain relationships
            var domains = indicators.Where(i => i.Type == IndicatorType.Domain).ToList();
            var domainGroups = domains
                .GroupBy(d => ExtractRootDomain(d.Value))
                .Where(g => g.Count() > 2);

            foreach (var group in domainGroups.Take(15))
            {
                var domainIndicators = group.ToList();
                var correlation = new CorrelationResult
                {
                    RelatedIndicators = domainIndicators,
                    CorrelationType = "INFRASTRUCTURE_CLUSTER",
                    ConfidenceScore = CalculateInfrastructureConfidence(domainIndicators.Count),
                    Description = $"Related infrastructure: {domainIndicators.Count} subdomains under {group.Key}",
                    AnalysisDetails = new Dictionary<string, object>
                    {
                        ["root_domain"] = group.Key,
                        ["subdomain_count"] = domainIndicators.Count,
                        ["threat_actors"] = domainIndicators.Select(d => d.ThreatActor).Where(a => !string.IsNullOrEmpty(a)).Distinct().ToList()
                    }
                };

                correlations.Add(correlation);
            }

            await Task.CompletedTask;
            return correlations;
        }

        // Confidence calculation methods
        private double CalculateCrossSourceConfidence(int sourceCount)
        {
            return Math.Min(0.5 + (sourceCount * 0.15), 0.95);
        }

        private double CalculateTemporalConfidence(int indicatorCount, int sourceCount)
        {
            var baseConfidence = Math.Min(indicatorCount * 0.02, 0.6);
            var sourceBonus = Math.Min(sourceCount * 0.1, 0.3);
            return Math.Min(baseConfidence + sourceBonus, 0.9);
        }

        private double CalculateActorConfidence(int indicatorCount, int sourceCount)
        {
            var baseConfidence = Math.Min(indicatorCount * 0.03, 0.7);
            var sourceBonus = Math.Min(sourceCount * 0.1, 0.25);
            return Math.Min(baseConfidence + sourceBonus, 0.95);
        }

        private double CalculateFamilyConfidence(int sampleCount, int sourceCount)
        {
            var baseConfidence = Math.Min(sampleCount * 0.04, 0.8);
            var sourceBonus = Math.Min(sourceCount * 0.05, 0.15);
            return Math.Min(baseConfidence + sourceBonus, 0.95);
        }

        private double CalculateInfrastructureConfidence(int subdomainCount)
        {
            return Math.Min(0.4 + (subdomainCount * 0.08), 0.85);
        }

        private double CalculatePivotConfidence(List<ThreatIndicator> indicators, List<string> actors, List<string> sources)
        {
            var baseConfidence = 0.5;
            var actorMultiplier = Math.Min(actors.Count * 0.2, 0.3);
            var sourceMultiplier = Math.Min(sources.Count * 0.1, 0.2);
            return Math.Min(baseConfidence + actorMultiplier + sourceMultiplier, 0.95);
        }

        // Helper methods
        private string DeterminePivotType(ThreatIndicator indicator)
        {
            return indicator.Type switch
            {
                IndicatorType.IpAddress => "C2_IP_OVERLAP",
                IndicatorType.Domain => "C2_DOMAIN_OVERLAP",
                _ => "INFRASTRUCTURE_OVERLAP"
            };
        }

        private List<string> CreatePivotEvidence(List<ThreatIndicator> indicators, List<string> actors, List<string> sources)
        {
            var evidence = new List<string>();
            evidence.Add($"Infrastructure shared by {actors.Count} threat actors");
            evidence.Add($"Confirmed by {sources.Count} independent intelligence sources");
            evidence.Add($"First observed: {indicators.Min(i => i.Created):yyyy-MM-dd}");
            evidence.Add($"Last observed: {indicators.Max(i => i.LastSeen):yyyy-MM-dd}");
            return evidence;
        }

        private string ExtractRootDomain(string domain)
        {
            var parts = domain.Split('.');
            if (parts.Length >= 2)
            {
                return string.Join(".", parts.TakeLast(2));
            }
            return domain;
        }
    }
}