using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
using RADAR.Core.Interfaces;
using RADAR.Core.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;

namespace RADAR.Core.Services
{
    public class ThreatIntelligenceOrchestrator
    {
        private readonly IEnumerable<IThreatIntelligenceCollector> _collectors;
        private readonly ICorrelationEngine _correlationEngine;
        private readonly AppConfig _config;
        private readonly ILogger<ThreatIntelligenceOrchestrator> _logger;

        public ThreatIntelligenceOrchestrator(
            IEnumerable<IThreatIntelligenceCollector> collectors,
            ICorrelationEngine correlationEngine,
            AppConfig config,
            ILogger<ThreatIntelligenceOrchestrator> logger)
        {
            _collectors = collectors;
            _correlationEngine = correlationEngine;
            _config = config;
            _logger = logger;
        }

        public async Task<ThreatIntelligenceReport> ExecuteFullAnalysisAsync()
        {
            var stopwatch = Stopwatch.StartNew();
            var report = new ThreatIntelligenceReport();

            try
            {
                _logger.LogInformation("🎯 Starting comprehensive threat intelligence analysis");

                var allIndicators = await CollectThreatIndicatorsAsync();
                report.TotalIndicators = allIndicators.Count;
                _logger.LogInformation("📊 Collected {Count} total threat indicators", allIndicators.Count);

                var allActors = await CollectThreatActorsAsync();
                report.TotalThreatActors = allActors.Count;
                _logger.LogInformation("👥 Collected {Count} total threat actors", allActors.Count);

                var correlations = await _correlationEngine.FindCorrelationsAsync(allIndicators);
                report.Correlations = correlations;
                _logger.LogInformation("🔗 Found {Count} correlations", correlations.Count);

                var pivots = await _correlationEngine.FindInfrastructurePivotsAsync(allIndicators);
                report.InfrastructurePivots = pivots;
                _logger.LogInformation("🏗️ Identified {Count} infrastructure pivots", pivots.Count);

                GenerateSummaryStatistics(report, allIndicators, allActors);

                report.AnalysisCompletedAt = DateTime.UtcNow;
                report.ProcessingTimeMs = stopwatch.ElapsedMilliseconds;

                _logger.LogInformation("✅ Analysis complete in {TimeMs}ms - {Indicators} indicators, {Correlations} correlations, {Pivots} pivots", 
                    stopwatch.ElapsedMilliseconds, allIndicators.Count, correlations.Count, pivots.Count);

                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Error during threat intelligence analysis");
                report.ErrorMessage = ex.Message;
                return report;
            }
            finally
            {
                stopwatch.Stop();
            }
        }

        private async Task<List<ThreatIndicator>> CollectThreatIndicatorsAsync()
        {
            var allIndicators = new List<ThreatIndicator>();
            var tasks = new List<Task<List<ThreatIndicator>>>();

            foreach (var collector in _collectors)
            {
                tasks.Add(CollectFromSourceAsync(collector));
            }

            var results = await Task.WhenAll(tasks);
            
            foreach (var indicators in results)
            {
                allIndicators.AddRange(indicators);
            }

            var deduplicatedIndicators = allIndicators
                .GroupBy(i => new { Value = i.Value.ToLowerInvariant(), Type = i.Type })
                .Select(g => g.OrderByDescending(i => i.Confidence).First()) // Keep highest confidence version
                .ToList();

            _logger.LogInformation("Deduplicated {Original} indicators to {Final} unique indicators", 
                allIndicators.Count, deduplicatedIndicators.Count);

            return deduplicatedIndicators;
        }

        private async Task<List<ThreatIndicator>> CollectFromSourceAsync(IThreatIntelligenceCollector collector)
        {
            try
            {
                _logger.LogInformation("Collecting indicators from {SourceName}", collector.SourceName);
                var indicators = await collector.CollectIndicatorsAsync();
                _logger.LogInformation("✅ {SourceName}: {Count} indicators", collector.SourceName, indicators.Count);
                return indicators;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to collect from {SourceName}", collector.SourceName);
                return new List<ThreatIndicator>();
            }
        }

        private async Task<List<ThreatActor>> CollectThreatActorsAsync()
        {
            var allActors = new List<ThreatActor>();
            var tasks = new List<Task<List<ThreatActor>>>();

            foreach (var collector in _collectors)
            {
                tasks.Add(CollectActorsFromSourceAsync(collector));
            }

            var results = await Task.WhenAll(tasks);
            
            foreach (var actors in results)
            {
                allActors.AddRange(actors);
            }

            // Deduplicate actors by name
            var deduplicatedActors = allActors
                .GroupBy(a => a.Name.ToLowerInvariant())
                .Select(g => MergeActorProfiles(g.ToList()))
                .ToList();

            return deduplicatedActors;
        }

        private async Task<List<ThreatActor>> CollectActorsFromSourceAsync(IThreatIntelligenceCollector collector)
        {
            try
            {
                _logger.LogInformation("Collecting threat actors from {SourceName}", collector.SourceName);
                var actors = await collector.CollectThreatActorsAsync();
                _logger.LogInformation("✅ {SourceName}: {Count} threat actors", collector.SourceName, actors.Count);
                return actors;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to collect threat actors from {SourceName}", collector.SourceName);
                return new List<ThreatActor>();
            }
        }

        private ThreatActor MergeActorProfiles(List<ThreatActor> actors)
        {
            if (actors.Count == 1) return actors.First();

            var primary = actors.OrderByDescending(a => a.Indicators.Count).First();
            
            foreach (var actor in actors.Skip(1))
            {
                primary.Aliases.AddRange(actor.Aliases.Except(primary.Aliases));
                primary.TTPs.AddRange(actor.TTPs.Except(primary.TTPs));
                primary.Indicators.AddRange(actor.Indicators.Except(primary.Indicators));
                primary.Targets.AddRange(actor.Targets.Except(primary.Targets));
                primary.Motivation.AddRange(actor.Motivation.Except(primary.Motivation));
                
                if (actor.FirstSeen < primary.FirstSeen)
                    primary.FirstSeen = actor.FirstSeen;
                    
                if (actor.LastActivity > primary.LastActivity)
                    primary.LastActivity = actor.LastActivity;
            }

            return primary;
        }

        private void GenerateSummaryStatistics(ThreatIntelligenceReport report, List<ThreatIndicator> indicators, List<ThreatActor> actors)
        {
            report.IndicatorsByType = indicators
                .GroupBy(i => i.Type)
                .ToDictionary(g => g.Key.ToString(), g => g.Count());

            report.IndicatorsBySource = indicators
                .GroupBy(i => i.Source)
                .ToDictionary(g => g.Key, g => g.Count());

            report.IndicatorsByConfidence = indicators
                .GroupBy(i => i.Confidence switch
                {
                    >= 90 => "High (90-100%)",
                    >= 70 => "Medium (70-89%)",
                    >= 50 => "Low (50-69%)",
                    _ => "Very Low (<50%)"
                })
                .ToDictionary(g => g.Key, g => g.Count());

            report.TopThreatActors = actors
                .OrderByDescending(a => a.Indicators.Count)
                .Take(10)
                .Select(a => new { 
                    Name = a.Name, 
                    IndicatorCount = a.Indicators.Count, 
                    TTPs = a.TTPs.Count 
                })
                .ToList();

            report.TopMalwareFamilies = indicators
                .Where(i => !string.IsNullOrEmpty(i.MalwareFamily))
                .GroupBy(i => i.MalwareFamily!)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .ToDictionary(g => g.Key, g => g.Count());

            report.HighConfidenceCorrelations = report.Correlations
                .Where(c => c.ConfidenceScore >= _config.Correlation.MinimumConfidenceThreshold)
                .OrderByDescending(c => c.ConfidenceScore)
                .ToList();
        }
    }

    public class ThreatIntelligenceReport
    {
        public DateTime AnalysisCompletedAt { get; set; }
        public long ProcessingTimeMs { get; set; }
        public int TotalIndicators { get; set; }
        public int TotalThreatActors { get; set; }
        public List<CorrelationResult> Correlations { get; set; } = new List<CorrelationResult>();
        public List<InfrastructurePivot> InfrastructurePivots { get; set; } = new List<InfrastructurePivot>();
        public Dictionary<string, int> IndicatorsByType { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> IndicatorsBySource { get; set; } = new Dictionary<string, int>();
        public Dictionary<string, int> IndicatorsByConfidence { get; set; } = new Dictionary<string, int>();
        public object TopThreatActors { get; set; } = new List<object>();
        public Dictionary<string, int> TopMalwareFamilies { get; set; } = new Dictionary<string, int>();
        public List<CorrelationResult> HighConfidenceCorrelations { get; set; } = new List<CorrelationResult>();
        public string? ErrorMessage { get; set; }
    }
}