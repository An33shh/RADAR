using System.Collections.Generic;
using System.Threading.Tasks;
using RADAR.Core.Models;
using RADAR.Core.Services;

namespace RADAR.Core.Interfaces
{
    public interface IThreatIntelligenceCollector
    {
        string SourceName { get; }
        Task<List<ThreatIndicator>> CollectIndicatorsAsync();
        Task<List<ThreatActor>> CollectThreatActorsAsync();
        Task<bool> IsHealthyAsync();
    }

    public interface ICorrelationEngine
    {
        Task<List<CorrelationResult>> FindCorrelationsAsync(List<ThreatIndicator> indicators);
        Task<List<InfrastructurePivot>> FindInfrastructurePivotsAsync(List<ThreatIndicator> indicators);
        Task<List<ThreatIndicator>> FindRelatedIndicatorsAsync(ThreatIndicator indicator);
    }

    public interface IReportGenerator
    {
        Task GenerateJsonReportAsync(List<CorrelationResult> correlations, string filePath);
        Task GenerateCsvReportAsync(List<ThreatIndicator> indicators, string filePath);
        Task GenerateThreatActorReportAsync(List<ThreatActor> actors, string filePath);
        Task GenerateExecutiveSummaryAsync(ThreatIntelligenceReport report, string filePath);
        Task GenerateInfrastructurePivotReportAsync(List<InfrastructurePivot> pivots, string filePath);
    }
}