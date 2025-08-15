# RADAR - Real-time Analysis & Detection of Adversarial Resources

**A C# threat intelligence aggregation platform for correlating IOCs across multiple sources and identifying infrastructure pivots between threat actors.**

## 🎯 Project Overview

RADAR is designed to automate the collection, correlation, and analysis of threat intelligence from multiple open-source feeds. The platform enables security researchers to identify previously unknown relationships between threat actors through shared infrastructure analysis.

## 🏗️ Current Implementation Status

### ✅ Foundation Layer (25% Complete)

**Core Data Models:**
- `ThreatIndicator` - Comprehensive IOC representation (IPs, domains, hashes, etc.)
- `ThreatActor` - Threat actor profiles with TTPs and attribution data
- `CorrelationResult` - Analysis findings and confidence scoring
- `InfrastructurePivot` - Shared infrastructure detection between threat actors

**Enterprise Architecture:**
- Dependency injection container setup
- Configuration management system
- Professional logging framework
- Multi-source threat feed configuration

**Threat Intelligence Sources (Configured):**
- AlienVault OTX - Community threat intelligence
- Abuse.ch MalwareBazaar - Malware indicators
- MITRE ATT&CK - TTPs and threat actor data

## 🚀 Getting Started

### Prerequisites
- .NET 8.0 SDK
- Visual Studio Code or Visual Studio

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/An33shh/RADAR.git
   cd RADAR
   ```

2. **Build the project:**
   ```bash
   cd RADAR.Core
   dotnet restore
   dotnet build
   ```

3. **Run RADAR:**
   ```bash
   dotnet run
   ```

### Configuration

Update `appsettings.json` with your API keys:
```json
{
  "AppConfig": {
    "ThreatFeeds": [
      {
        "Name": "AlienVault_OTX",
        "ApiKey": "YOUR_OTX_API_KEY_HERE"
      }
    ]
  }
}
```

## 📁 Project Structure

```
RADAR/
├── RADAR.sln
└── RADAR.Core/
    ├── Models/                 # Core data structures
    │   ├── ThreatIndicator.cs
    │   ├── ThreatActor.cs
    │   └── CorrelationResult.cs
    ├── Configuration/          # App configuration
    │   └── AppConfig.cs
    ├── Interfaces/             # Service contracts
    │   └── IThreatIntelligenceCollector.cs
    ├── Collectors/             # API integrations (Coming Next)
    ├── Services/               # Core business logic (Coming Next)
    ├── appsettings.json        # Application settings
    └── Program.cs              # Application entry point
```

## 🛠️ Technical Features

- **Multi-source Integration** - Unified interface for diverse threat feeds
- **Enterprise Patterns** - Dependency injection, logging, configuration management
- **Extensible Design** - Easy addition of new threat intelligence sources
- **Type Safety** - Comprehensive C# models with validation
- **Professional Logging** - Structured logging with Microsoft.Extensions.Logging

## 🔄 Development Roadmap

### Phase 1: Foundation ✅
- [x] Core data models and interfaces
- [x] Configuration system
- [x] Dependency injection setup
- [x] Application bootstrap

### Phase 2: Data Collection (Next)
- [ ] AlienVault OTX API collector
- [ ] Abuse.ch API collector  
- [ ] MITRE ATT&CK data parser
- [ ] Rate limiting and error handling

### Phase 3: Analysis Engine (Planned)
- [ ] IOC correlation algorithms
- [ ] Infrastructure pivot detection
- [ ] Threat actor attribution
- [ ] Confidence scoring system

### Phase 4: Reporting & Visualization (Planned)
- [ ] JSON/CSV report generation
- [ ] Threat intelligence dashboards
- [ ] API endpoints for integration
- [ ] Automated alerting

## 🔧 Tech Stack

- **Language:** C# 8.0+
- **Framework:** .NET 8.0
- **Dependencies:** Microsoft.Extensions.* (DI, Logging, Configuration)
- **APIs:** AlienVault OTX, Abuse.ch, MITRE ATT&CK
- **Architecture:** Clean Architecture with dependency injection

## 📊 Sample Output

```
🎯 RADAR - Real-time Analysis & Detection of Adversarial Resources
================================================================

📋 Configuration Summary:
   Active Threat Feeds: 3
   Max Concurrent Requests: 5
   Request Timeout: 00:00:30
   Correlation Confidence Threshold: 70.0%

📡 Active Feeds:
   • AlienVault_OTX (Refresh: 01:00:00)
   • AbuseCH_MalwareBazaar (Refresh: 02:00:00)
   • MITRE_ATTCK (Refresh: 24.00:00:00)

✅ RADAR foundation initialized successfully!
```

## 🤝 Contributing

This project is part of a personal learning initiative focused on threat intelligence and C# development. Future enhancements will include advanced correlation algorithms and real-time threat detection capabilities.

## 📄 License

MIT License - see LICENSE file for details.

---

**Built with ❤️ for the cybersecurity community**
