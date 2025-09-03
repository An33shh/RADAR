using Microsoft.Extensions.Logging;
using RADAR.Core.Configuration;
using RADAR.Core.Interfaces;
using RADAR.Core.Models;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

namespace RADAR.Core.Collectors
{
    public abstract class BaseThreatCollector : IThreatIntelligenceCollector
    {
        protected readonly HttpClient _httpClient;
        protected readonly ThreatFeedConfig _config;
        protected readonly ILogger _logger;
        protected readonly JsonSerializerOptions _jsonOptions;

        public abstract string SourceName { get; }

        protected BaseThreatCollector(HttpClient httpClient, ThreatFeedConfig config, ILogger logger)
        {
            _httpClient = httpClient;
            _config = config;
            _logger = logger;
            
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true,
                PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
            };

            ConfigureHttpClient();
        }

        private void ConfigureHttpClient()
        {
            _httpClient.Timeout = TimeSpan.FromSeconds(30);
            
            foreach (var header in _config.Headers)
            {
                _httpClient.DefaultRequestHeaders.Add(header.Key, header.Value);
            }

            if (!string.IsNullOrEmpty(_config.ApiKey))
            {
                AddAuthenticationHeader();
            }
        }

        protected virtual void AddAuthenticationHeader()
        {
            if (!string.IsNullOrEmpty(_config.ApiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("X-OTX-API-KEY", _config.ApiKey);
            }
        }

        public abstract Task<List<ThreatIndicator>> CollectIndicatorsAsync();
        public abstract Task<List<ThreatActor>> CollectThreatActorsAsync();

        public virtual async Task<bool> IsHealthyAsync()
        {
            try
            {
                var response = await _httpClient.GetAsync(_config.BaseUrl);
                return response.IsSuccessStatusCode;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Health check failed for {SourceName}", SourceName);
                return false;
            }
        }

        protected async Task<T?> GetJsonAsync<T>(string endpoint) where T : class
        {
            try
            {
                _logger.LogDebug("Fetching data from {Endpoint}", endpoint);
                
                var response = await _httpClient.GetAsync(endpoint);
                response.EnsureSuccessStatusCode();

                var jsonContent = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<T>(jsonContent, _jsonOptions);
            }
            catch (HttpRequestException ex)
            {
                _logger.LogError(ex, "HTTP error fetching from {Endpoint}", endpoint);
                return null;
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "JSON parsing error from {Endpoint}", endpoint);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error fetching from {Endpoint}", endpoint);
                return null;
            }
        }

        protected ThreatIndicator CreateIndicator(string value, IndicatorType type, string? description = null)
        {
            return new ThreatIndicator
            {
                Value = value,
                Type = type,
                Source = SourceName,
                Description = description,
                Confidence = 75 
            };
        }

        protected void ValidateConfiguration()
        {
            if (string.IsNullOrEmpty(_config.BaseUrl))
                throw new InvalidOperationException($"BaseUrl is required for {SourceName}");
        }
    }
}