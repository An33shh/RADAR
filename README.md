# RADAR - Real-time Analysis & Detection of Adversarial Resources

**A C# threat intelligence aggregation platform for correlating IOCs across multiple sources and identifying infrastructure pivots between threat actors.**

## 🎯 Project Overview

RADAR is designed to automate the collection, correlation, and analysis of threat intelligence from multiple open-source feeds. The platform enables security researchers to identify previously unknown relationships between threat actors through shared infrastructure analysis.

## 🏗️ RADAR v1.0 Features

**Enterprise-Grade Architecture:**
- Complete dependency injection container with service registration
- Comprehensive configuration management with secure local overrides
- Professional logging framework with structured output
- Multi-threaded threat feed orchestration
- Robust error handling and rate limiting

**Threat Intelligence Collectors (Fully Implemented):**
- **AlienVault OTX** - Community threat intelligence and IOC feeds
- **Abuse.ch MalwareBazaar** - Malware samples and hash indicators  
- **MITRE ATT&CK** - Tactics, techniques, and threat actor profiles

**Advanced Correlation Engine:**
- Cross-source IOC validation (same indicators from multiple feeds)
- Temporal correlation analysis (coordinated threat activity detection)
- Threat actor attribution clustering
- Malware family relationship mapping
- Infrastructure pivot detection (shared C2 infrastructure)
- Confidence scoring algorithms

**Comprehensive Data Models:**
- `ThreatIndicator` - Complete IOC representation with metadata
- `ThreatActor` - Threat actor profiles with TTPs and attribution
- `CorrelationResult` - Analysis findings with confidence scoring
- `InfrastructurePivot` - Shared infrastructure detection between actors

**Professional Reporting System:**
- JSON reports for programmatic analysis
- CSV exports for spreadsheet analysis
- Markdown executive summaries
- Infrastructure pivot analysis reports
- Session-based data storage and historical analysis

### 🔒 Security Features
- Secure configuration management (API keys in local files only)
- Comprehensive .gitignore for sensitive data protection
- Environment variable support for production deployments
- API key validation and health checking

## 🚀 Getting Started

### Prerequisites
- .NET 8.0 SDK
- Visual Studio Code or Visual Studio
- API keys for threat intelligence sources

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/An33sh/RADAR.git
   cd RADAR
   ```

2. **Set up secure configuration:**
   ```bash
   cd RADAR.Core
   
   # Copy the template to create your local config
   cp appsettings.json appsettings.local.json
   
   # Edit appsettings.local.json with your API keys
   # The main appsettings.json has empty API key fields for security
   ```

3. **Get API Keys:**
   - **AlienVault OTX**: Register at https://otx.alienvault.com and get your API key
   - **Abuse.ch**: Request API access at https://bazaar.abuse.ch/api/
   - **MITRE ATT&CK**: No API key required (public data)

4. **Update your configuration:**
   ```json
   {
     "AppConfig": {
       "ThreatFeeds": [
         {
           "Name": "AlienVault_OTX",
           "ApiKey": "YOUR_OTX_API_KEY_HERE"
         },
         {
           "Name": "AbuseCH_MalwareBazaar",
           "ApiKey": "YOUR_ABUSE_API_KEY_HERE"
         }
       ]
     }
   }
   ```

5. **Build and run:**
   ```bash
   dotnet restore
   dotnet build
   dotnet run
   ```

## 🛠️ Technical Features

### Data Collection
- **Multi-source Integration** - Unified interface for diverse threat feeds
- **Rate Limiting** - Respects API limits and implements retry logic
- **Health Monitoring** - Automatic feed availability checking
- **Deduplication** - Intelligent IOC deduplication across sources

### Analysis Engine
- **Cross-Source Validation** - Confirms IOCs across multiple intelligence sources
- **Temporal Analysis** - Detects coordinated threat campaigns
- **Infrastructure Pivoting** - Identifies shared C2 infrastructure between threat actors
- **Confidence Scoring** - Mathematical confidence calculations for all correlations

### Enterprise Features
- **Structured Logging** - Comprehensive logging with Microsoft.Extensions.Logging
- **Dependency Injection** - Clean architecture with IoC container
- **Configuration Management** - Hierarchical config with secure local overrides
- **Session Management** - Historical analysis and data persistence

## 📊 Sample Analysis Output

```
🎯 RADAR Analysis Results
========================
⏱️  Processing Time: 45,230ms
📊 Total Indicators: 2,847
👥 Total Threat Actors: 23
🔗 Correlations Found: 156
🏗️  Infrastructure Pivots: 8

📈 Indicators by Type:
   • FileHash: 1,245
   • Domain: 892
   • IpAddress: 445
   • Url: 265

📡 Indicators by Source:
   • AbuseCH_MalwareBazaar: 1,245
   • AlienVault_OTX: 1,378
   • MITRE_ATT&CK: 224

🎯 High-Confidence Correlations:
   • CROSS_SOURCE_VALIDATION: IOC confirmed by 3 independent sources (95.0%)
   • MALWARE_FAMILY_CLUSTER: Emotet family: 67 related samples (88.5%)
   • INFRASTRUCTURE_CLUSTER: 12 subdomains under suspicious-domain.com (82.3%)

🏗️ Infrastructure Pivots:
   • C2_IP_OVERLAP: 192.168.1.100 shared by 3 actors (91.2%)
   • C2_DOMAIN_OVERLAP: evil-c2.net shared by 2 actors (85.7%)
```

## 🔄 Future Enhancements

- REST API endpoints for integration
- Real-time threat monitoring dashboard
- Machine learning correlation algorithms
- SIEM platform integrations
- Docker containerization
- Advanced threat hunting workflows
- Custom threat feed support
- Performance optimization for large datasets

## 🔧 Tech Stack

- **Language:** C# 12 (.NET 8.0)
- **Architecture:** Clean Architecture with dependency injection
- **Dependencies:** Microsoft.Extensions.* ecosystem
- **APIs:** AlienVault OTX, Abuse.ch MalwareBazaar, MITRE ATT&CK
- **Data Format:** JSON, CSV, Markdown
- **Logging:** Structured logging with console output

## 🤝 Contributing

RADAR demonstrates advanced C# development patterns including:
- Enterprise application architecture
- Secure configuration management
- Professional logging and monitoring
- Multi-threaded data processing
- Mathematical correlation algorithms

## 📄 License

RADAR is proprietary software. This source code is made available for demonstration and portfolio purposes only.

**Commercial licensing available** - Contact aneesharunjunai@gmail.com for business inquiries.

## 🔒 Usage Rights

- ✅ View source code for learning
- ✅ Academic research and education  
- ❌ Commercial use
- ❌ Redistribution or resale
- ❌ Creating competing products

## 🔒 Security Notice

- Never commit API keys to version control
- Use `appsettings.local.json` for sensitive configuration
- Rotate API keys regularly
- Monitor for exposed credentials in commit history

---

**Built with ❤️ for the cybersecurity community**

*RADAR v1.0 - Bringing enterprise-grade threat intelligence to security researchers*
