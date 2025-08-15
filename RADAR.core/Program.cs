using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
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

                await Task.Delay(100); // This is just to simulate some startup delay
                logger.LogInformation("Foundation setup complete. Ready for threat intelligence collection.");
                
                Console.WriteLine("\n✅ RADAR foundation initialized successfully!");
                Console.WriteLine("📊 Ready to collect threat intelligence data");
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
        }
    }
}