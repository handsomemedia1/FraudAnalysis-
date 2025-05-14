# PowerShell Fraud Detection System

A cross-platform activity correlator for fraud detection built with PowerShell.

## Features

- Real-time monitoring of activities across multiple systems
- Temporal pattern analysis to identify suspicious sequences
- Customizable detection rules
- Web-based dashboard for monitoring and alerts
- Automatic log collection from Windows, network devices, and SQL servers

## Requirements

- Windows with PowerShell 5.1 or higher
- Required PowerShell modules:
  - Import-Excel
  - Posh-SSH (for network device monitoring)
  - SqlServer (for SQL monitoring)

## Installation

1. Clone this repository
2. Run `.\src\Deploy-FraudDetectionSystem.ps1`
3. Configure your data sources in `config\settings.json`
4. Access the dashboard at http://localhost:10000

## Configuration

Edit the `config\settings.json` file to specify:
- Log and report paths
- Windows event logs to monitor
- Network devices to connect to
- SQL servers to query
- Detection rules and thresholds

## Screenshots

![Dashboard Screenshot]
![image](https://github.com/user-attachments/assets/2406fcee-2212-4adb-b94e-340af756719a)
![image](https://github.com/user-attachments/assets/4746f4b8-5297-4ba3-ad4a-2b19f79eb9c6)

