using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
using RADAR.Core.Collectors;
using RADAR.Core.Interfaces;
using RADAR.Core.Services;
using RADAR.Core.Models;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace RADAR.Core
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("🎯 RADAR - Real-time Analysis & Detection of Adversarial Resources");
            Console.WriteLine("================================================================");
            Console.WriteLine();

            try
            {
                var configuration = new ConfigurationBuilder()
                    .SetBasePath(Directory.GetCurrentDirectory())
                    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                    .Build();

                var services = new ServiceCollection();
                ConfigureServices(services, configuration);

                var serviceProvider = services.BuildServiceProvider();
                var logger = serviceProvider.GetRequiredService<ILogger<Program>>();

                logger.LogInformation("RADAR starting up...");

                var appConfig = serviceProvider.GetRequiredService<AppConfig>();
                
                DisplayConfigurationSummary(appConfig, logger);

                var orchestrator = serviceProvider.GetRequiredService<ThreatIntelligenceOrchestrator>();
                var report = await orchestrator.ExecuteFullAnalysisAsync();

                await GenerateReportsAsync(serviceProvider, report);

                DisplayAnalysisReport(report);
                
                Console.WriteLine("\nPress any key to exit...");
                Console.ReadKey();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error starting RADAR: {ex.Message}");
                Console.WriteLine($"Stack trace: {ex.StackTrace}");
            }
        }

        private static void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            services.AddLogging(builder =>
            {
                builder.AddConsole();
                builder.AddConfiguration(configuration.GetSection("Logging"));
            });

            var appConfig = new AppConfig();
            configuration.GetSection("AppConfig").Bind(appConfig);
            services.AddSingleton(appConfig);

            services.AddHttpClient();

            RegisterCollectors(services, appConfig);

            services.AddScoped<ICorrelationEngine, CorrelationEngine>();
            
            services.AddScoped<IReportGenerator, ReportGenerator>();
            
            services.AddScoped<DataStorageService>();
            
            services.AddScoped<ThreatIntelligenceOrchestrator>();
        }

        private static void RegisterCollectors(IServiceCollection services, AppConfig config)
        {
            foreach (var feedConfig in config.ThreatFeeds.Where(f => f.IsActive))
            {
                switch (feedConfig.Name.ToLowerInvariant())
                {
                    case "alienvault_otx":
                        services.AddScoped<IThreatIntelligenceCollector>(provider =>
                        {
                            var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient();
                            var logger = provider.GetRequiredService<ILogger<AlienVaultCollector>>();
                            return new AlienVaultCollector(httpClient, feedConfig, logger);
                        });
                        break;

                    case "abusech_malwarebazaar":
                        services.AddScoped<IThreatIntelligenceCollector>(provider =>
                        {
                            var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient();
                            var logger = provider.GetRequiredService<ILogger<AbuseCHCollector>>();
                            return new AbuseCHCollector(httpClient, feedConfig, logger);
                        });
                        break;
                        
                    case "mitre_attck":
                        services.AddScoped<IThreatIntelligenceCollector>(provider =>
                        {
                            var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient();
                            var logger = provider.GetRequiredService<ILogger<MitreAttckCollector>>();
                            return new MitreAttckCollector(httpClient, feedConfig, logger);
                        });
                        break;
                }
            }
        }

        private static void DisplayConfigurationSummary(AppConfig config, ILogger logger)
        {
            logger.LogInformation("📋 Configuration Summary:");
            logger.LogInformation($"   Active Threat Feeds: {config.ThreatFeeds.Count(f => f.IsActive)}");
            logger.LogInformation($"   Max Concurrent Requests: {config.MaxConcurrentRequests}");
            logger.LogInformation($"   Request Timeout: {config.RequestTimeout}");
            logger.LogInformation($"   Output Directory: {config.OutputDirectory}");
            logger.LogInformation($"   Correlation Confidence Threshold: {config.Correlation.MinimumConfidenceThreshold:P1}");
            
            Console.WriteLine($"📡 Active Feeds:");
            foreach (var feed in config.ThreatFeeds.Where(f => f.IsActive))
            {
                Console.WriteLine($"   • {feed.Name} (Refresh: {feed.RefreshInterval})");
            }
            
            Console.WriteLine("\n🔄 Starting comprehensive threat intelligence analysis...");
        }

        private static void DisplayAnalysisReport(ThreatIntelligenceReport report)
        {
            Console.WriteLine("\n🎯 RADAR Analysis Results");
            Console.WriteLine("========================");
            Console.WriteLine($"⏱️  Processing Time: {report.ProcessingTimeMs:N0}ms");
            Console.WriteLine($"📊 Total Indicators: {report.TotalIndicators:N0}");
            Console.WriteLine($"👥 Total Threat Actors: {report.TotalThreatActors:N0}");
            Console.WriteLine($"🔗 Correlations Found: {report.Correlations.Count:N0}");
            Console.WriteLine($"🏗️  Infrastructure Pivots: {report.InfrastructurePivots.Count:N0}");

            if (report.IndicatorsByType.Any())
            {
                Console.WriteLine("\n📈 Indicators by Type:");
                foreach (var kvp in report.IndicatorsByType.OrderByDescending(x => x.Value))
                {
                    Console.WriteLine($"   • {kvp.Key}: {kvp.Value:N0}");
                }
            }

            if (report.IndicatorsBySource.Any())
            {
                Console.WriteLine("\n📡 Indicators by Source:");
                foreach (var kvp in report.IndicatorsBySource.OrderByDescending(x => x.Value))
                {
                    Console.WriteLine($"   • {kvp.Key}: {kvp.Value:N0}");
                }
            }

            if (report.TopMalwareFamilies.Any())
            {
                Console.WriteLine("\n🦠 Top Malware Families:");
                foreach (var kvp in report.TopMalwareFamilies.Take(5))
                {
                    Console.WriteLine($"   • {kvp.Key}: {kvp.Value:N0} samples");
                }
            }

            if (report.HighConfidenceCorrelations.Any())
            {
                Console.WriteLine("\n🎯 High-Confidence Correlations:");
                foreach (var correlation in report.HighConfidenceCorrelations.Take(5))
                {
                    Console.WriteLine($"   • {correlation.CorrelationType}: {correlation.Description} ({correlation.ConfidenceScore:P1})");
                }
            }

            if (report.InfrastructurePivots.Any())
            {
                Console.WriteLine("\n🏗️ Infrastructure Pivots:");
                foreach (var pivot in report.InfrastructurePivots.Take(5))
                {
                    Console.WriteLine($"   • {pivot.PivotType}: {pivot.SharedInfrastructure.Value} shared by {pivot.ThreatActors.Count} actors ({pivot.ConfidenceScore:P1})");
                }
            }

            if (!string.IsNullOrEmpty(report.ErrorMessage))
            {
                Console.WriteLine($"\n❌ Errors: {report.ErrorMessage}");
            }
            
            Console.WriteLine($"\n✅ Analysis completed at {report.AnalysisCompletedAt:yyyy-MM-dd HH:mm:ss} UTC");
        }

        private static async Task GenerateReportsAsync(IServiceProvider serviceProvider, ThreatIntelligenceReport report)
        {
            try
            {
                var reportGenerator = serviceProvider.GetRequiredService<IReportGenerator>();
                var dataStorage = serviceProvider.GetRequiredService<DataStorageService>();
                var config = serviceProvider.GetRequiredService<AppConfig>();
                var logger = serviceProvider.GetRequiredService<ILogger<Program>>();

                logger.LogInformation("📄 Generating comprehensive reports...");

                Directory.CreateDirectory(config.OutputDirectory);
                var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");

                var indicators = new List<ThreatIndicator>();
                var actors = new List<ThreatActor>();

                var correlationReportPath = Path.Combine(config.OutputDirectory, $"correlations-{timestamp}.json");
                await reportGenerator.GenerateJsonReportAsync(report.Correlations, correlationReportPath);

                var csvReportPath = Path.Combine(config.OutputDirectory, $"indicators-{timestamp}.csv");
                await reportGenerator.GenerateCsvReportAsync(indicators, csvReportPath);

                var actorReportPath = Path.Combine(config.OutputDirectory, $"threat-actors-{timestamp}.json");
                await reportGenerator.GenerateThreatActorReportAsync(actors, actorReportPath);

                var summaryPath = Path.Combine(config.OutputDirectory, $"executive-summary-{timestamp}.md");
                await reportGenerator.GenerateExecutiveSummaryAsync(report, summaryPath);

                var pivotReportPath = Path.Combine(config.OutputDirectory, $"infrastructure-pivots-{timestamp}.json");
                await reportGenerator.GenerateInfrastructurePivotReportAsync(report.InfrastructurePivots, pivotReportPath);

                await dataStorage.SaveAnalysisSessionAsync(report, indicators, actors);

                await dataStorage.CleanupOldDataAsync();

                logger.LogInformation("📊 All reports generated successfully in {Directory}", config.OutputDirectory);
                
                Console.WriteLine($"\n📄 Reports Generated:");
                Console.WriteLine($"   • Correlations: {Path.GetFileName(correlationReportPath)}");
                Console.WriteLine($"   • Indicators CSV: {Path.GetFileName(csvReportPath)}");
                Console.WriteLine($"   • Threat Actors: {Path.GetFileName(actorReportPath)}");
                Console.WriteLine($"   • Executive Summary: {Path.GetFileName(summaryPath)}");
                Console.WriteLine($"   • Infrastructure Pivots: {Path.GetFileName(pivotReportPath)}");
                Console.WriteLine($"   • All files saved to: {config.OutputDirectory}");
            }
            catch (Exception ex)
            {
                var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
                logger.LogError(ex, "Error generating reports");
                Console.WriteLine($"❌ Error generating reports: {ex.Message}");
            }
        }
    }
}