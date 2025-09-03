using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
using RADAR.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace RADAR.Core.Collectors
{
    public class AbuseCHCollector : BaseThreatCollector
    {
        public override string SourceName => "Abuse.ch_MalwareBazaar";

        public AbuseCHCollector(HttpClient httpClient, ThreatFeedConfig config, ILogger<AbuseCHCollector> logger)
            : base(httpClient, config, logger)
        {
            ValidateConfiguration();
        }

        protected override void AddAuthenticationHeader()
        {
            // Abuse.ch uses Auth-Key header (confirmed by curl test)
            if (!string.IsNullOrEmpty(_config.ApiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("Auth-Key", _config.ApiKey);
            }
        }

        public override async Task<List<ThreatIndicator>> CollectIndicatorsAsync()
        {
            var indicators = new List<ThreatIndicator>();

            try
            {
                _logger.LogInformation("Starting malware hash collection from Abuse.ch MalwareBazaar");

                // Get samples using both selectors with multiple batches
                var allSamples = new List<AbuseCHSample>();

                // Get time-based samples (last 60 minutes)
                var timeSamples = await GetRecentMalwareSamplesAsync("time");
                if (timeSamples?.Data != null)
                {
                    allSamples.AddRange(timeSamples.Data);
                    _logger.LogInformation("Retrieved {Count} samples from time-based query", timeSamples.Data.Count);
                }

                // Get count-based samples (last 100)  
                var recentSamples = await GetRecentMalwareSamplesAsync("100");
                if (recentSamples?.Data != null)
                {
                    allSamples.AddRange(recentSamples.Data);
                    _logger.LogInformation("Retrieved {Count} samples from count-based query", recentSamples.Data.Count);
                }

                // Add delay between requests to respect rate limits
                await Task.Delay(2000);

                // Try additional queries for different time windows if API supports it
                var additionalSamples = await TryGetAdditionalSamplesAsync();
                if (additionalSamples != null)
                {
                    allSamples.AddRange(additionalSamples);
                }

                // Remove duplicates based on SHA256 hash
                var uniqueSamples = allSamples
                    .GroupBy(s => s.Sha256Hash)
                    .Select(g => g.First())
                    .Take(2000); // Process up to 2000 unique samples

                // Convert samples to threat indicators  
                foreach (var sample in uniqueSamples)
                {
                    var indicator = ConvertToThreatIndicator(sample);
                    if (indicator != null)
                    {
                        indicators.Add(indicator);
                    }
                }

                _logger.LogInformation("Collected {Count} unique malware indicators from Abuse.ch ({Total} total samples processed)", 
                    indicators.Count, allSamples.Count);
                return indicators;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error collecting indicators from Abuse.ch");
                return indicators;
            }
        }

        private async Task<List<AbuseCHSample>?> TryGetAdditionalSamplesAsync()
        {
            try
            {
                // Try to get more samples using alternative queries if they exist
                // This is speculative - some APIs support date ranges or different selectors
                var samples = new List<AbuseCHSample>();

                // You could add more creative queries here based on API documentation
                // For now, we'll return null and rely on the two main selectors
                return null;
            }
            catch
            {
                return null;
            }
        }

        public override async Task<List<ThreatActor>> CollectThreatActorsAsync()
        {
            var actors = new List<ThreatActor>();

            try
            {
                _logger.LogInformation("Analyzing malware families for threat actor attribution");

                // Get samples using both selectors
                var timeSamples = await GetRecentMalwareSamplesAsync("time");
                var recentSamples = await GetRecentMalwareSamplesAsync("100");

                var allSamples = new List<AbuseCHSample>();
                
                if (timeSamples?.Data != null)
                    allSamples.AddRange(timeSamples.Data);
                
                if (recentSamples?.Data != null)
                    allSamples.AddRange(recentSamples.Data);

                // Remove duplicates and group by signature OR tags
                var uniqueSamples = allSamples
                    .GroupBy(s => s.Sha256Hash)
                    .Select(g => g.First())
                    .ToList();

                // Group by signature (malware family)
                var signatureGroups = uniqueSamples
                    .Where(s => !string.IsNullOrEmpty(s.Signature))
                    .GroupBy(s => s.Signature)
                    .Where(g => g.Count() > 1);

                // Group by tags if signature grouping is insufficient
                var tagGroups = uniqueSamples
                    .Where(s => s.Tags != null && s.Tags.Any())
                    .SelectMany(s => s.Tags!.Select(tag => new { Sample = s, Tag = tag }))
                    .Where(x => IsValidMalwareTag(x.Tag))
                    .GroupBy(x => x.Tag)
                    .Where(g => g.Count() > 2)
                    .Select(g => new { Family = g.Key, Samples = g.Select(x => x.Sample).ToList() });

                // Create actors from signature groups
                foreach (var group in signatureGroups.Take(25))
                {
                    var actor = CreateThreatActorFromFamily(group.Key!, group.ToList());
                    actors.Add(actor);
                }

                // Create actors from tag groups if we don't have enough from signatures
                if (actors.Count < 10)
                {
                    foreach (var group in tagGroups.Take(15))
                    {
                        var actor = CreateThreatActorFromFamily(group.Family, group.Samples);
                        actors.Add(actor);
                    }
                }

                _logger.LogInformation("Identified {Count} potential threat actors from malware families", actors.Count);
                return actors;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error analyzing threat actors from Abuse.ch");
                return actors;
            }
        }

        private bool IsValidMalwareTag(string tag)
        {
            var validTags = new[] { "mirai", "emotet", "trickbot", "cobalt", "amadey", "lummastealer", 
                                   "coinminer", "ransomware", "trojan", "backdoor", "botnet", "stealer" };
            return validTags.Any(validTag => tag.ToLowerInvariant().Contains(validTag));
        }

        private async Task<AbuseCHResponse?> GetRecentMalwareSamplesAsync(string selector = "time")
        {
            try
            {
                // Use form data with specified selector parameter
                var formData = new List<KeyValuePair<string, string>>
                {
                    new KeyValuePair<string, string>("query", "get_recent"),
                    new KeyValuePair<string, string>("selector", selector)
                };

                var content = new FormUrlEncodedContent(formData);
                var response = await _httpClient.PostAsync($"{_config.BaseUrl}/api/v1/", content);
                response.EnsureSuccessStatusCode();

                var jsonResponse = await response.Content.ReadAsStringAsync();
                return System.Text.Json.JsonSerializer.Deserialize<AbuseCHResponse>(jsonResponse, _jsonOptions);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching recent malware samples from Abuse.ch with selector {Selector}", selector);
                return null;
            }
        }

        private ThreatIndicator? ConvertToThreatIndicator(AbuseCHSample sample)
        {
            if (string.IsNullOrEmpty(sample.Sha256Hash)) return null;

            return new ThreatIndicator
            {
                Value = sample.Sha256Hash,
                Type = IndicatorType.FileHash,
                Source = SourceName,
                Description = $"Malware: {sample.Signature ?? "Unknown"} ({sample.FileType ?? "Unknown"})",
                MalwareFamily = sample.Signature,
                Tags = CreateTagsFromSample(sample),
                Confidence = 90 // High confidence for Abuse.ch data
            };
        }

        private List<string> CreateTagsFromSample(AbuseCHSample sample)
        {
            var tags = new List<string>();

            // Add signature tags
            if (!string.IsNullOrEmpty(sample.Signature))
                tags.Add($"malware:{sample.Signature}");

            // Add file type tags
            if (!string.IsNullOrEmpty(sample.FileType))
                tags.Add($"filetype:{sample.FileType}");

            // Add tags from the sample's tag array
            if (sample.Tags != null)
            {
                tags.AddRange(sample.Tags.Take(5)); // Limit to 5 tags
            }

            // Add size category
            if (sample.FileSize > 0)
            {
                var sizeCategory = sample.FileSize switch
                {
                    < 1024 => "tiny",
                    < 1024 * 1024 => "small",
                    < 10 * 1024 * 1024 => "medium",
                    _ => "large"
                };
                tags.Add($"size:{sizeCategory}");
            }

            return tags;
        }

        private ThreatActor CreateThreatActorFromFamily(string familyName, List<AbuseCHSample> samples)
        {
            var actor = new ThreatActor
            {
                Name = $"{familyName}_Operator",
                Country = "Unknown"
            };

            // Add malware family as primary TTP
            actor.TTPs.Add($"Uses {familyName} malware");
            
            // Analyze file types used by this actor
            var fileTypes = samples.Select(s => s.FileType).Distinct().Where(ft => !string.IsNullOrEmpty(ft));
            foreach (var fileType in fileTypes.Take(5))
            {
                actor.TTPs.Add($"Deploys {fileType} files");
            }

            // Analyze target platforms
            var platforms = samples.SelectMany(s => s.Tags ?? new List<string>())
                .Where(tag => tag.Contains("win") || tag.Contains("linux") || tag.Contains("android"))
                .Distinct()
                .Take(3);
            
            foreach (var platform in platforms)
            {
                actor.TTPs.Add($"Targets {platform} platform");
            }

            // Add file hashes as indicators
            foreach (var sample in samples.Take(25)) // Increased to 25 hashes per actor
            {
                if (!string.IsNullOrEmpty(sample.Sha256Hash))
                {
                    var indicator = new ThreatIndicator
                    {
                        Value = sample.Sha256Hash,
                        Type = IndicatorType.FileHash,
                        Source = SourceName,
                        MalwareFamily = familyName,
                        Confidence = 90
                    };
                    actor.Indicators.Add(indicator);
                }
            }

            return actor;
        }
    }

    // Enhanced data models matching the actual Abuse.ch API response
    public class AbuseCHResponse
    {
        [JsonPropertyName("query_status")]
        public string? QueryStatus { get; set; }

        [JsonPropertyName("data")]
        public List<AbuseCHSample>? Data { get; set; }
    }

    public class AbuseCHSample
    {
        [JsonPropertyName("sha256_hash")]
        public string Sha256Hash { get; set; } = string.Empty;

        [JsonPropertyName("sha3_384_hash")]
        public string? Sha3Hash { get; set; }

        [JsonPropertyName("sha1_hash")]
        public string? Sha1Hash { get; set; }

        [JsonPropertyName("md5_hash")]
        public string? Md5Hash { get; set; }

        [JsonPropertyName("first_seen")]
        public string? FirstSeen { get; set; }

        [JsonPropertyName("last_seen")]
        public string? LastSeen { get; set; }

        [JsonPropertyName("file_name")]
        public string? FileName { get; set; }

        [JsonPropertyName("file_size")]
        public long FileSize { get; set; }

        [JsonPropertyName("file_type_mime")]
        public string? FileTypeMime { get; set; }

        [JsonPropertyName("file_type")]
        public string? FileType { get; set; }

        [JsonPropertyName("reporter")]
        public string? Reporter { get; set; }

        [JsonPropertyName("origin_country")]
        public string? OriginCountry { get; set; }

        [JsonPropertyName("signature")]
        public string? Signature { get; set; }

        [JsonPropertyName("imphash")]
        public string? ImpHash { get; set; }

        [JsonPropertyName("tags")]
        public List<string>? Tags { get; set; }

        [JsonPropertyName("intelligence")]
        public AbuseCHIntelligence? Intelligence { get; set; }
    }

    public class AbuseCHIntelligence
    {
        [JsonPropertyName("clamav")]
        public string? ClamAV { get; set; }

        [JsonPropertyName("downloads")]
        public string? Downloads { get; set; }

        [JsonPropertyName("uploads")]
        public string? Uploads { get; set; }
    }
}