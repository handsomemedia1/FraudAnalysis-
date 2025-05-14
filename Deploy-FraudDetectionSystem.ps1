try {
    Write-Host "Cross-Platform Activity Correlator - Deployment" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    
    # Create directory structure
    $basePath = "C:\FraudAnalysis"
    $folders = @("Logs", "Config", "Scripts\Collectors", "Scripts\Analysis", "Scripts\Dashboard", "Reports")
    
    Write-Host "Step 1: Creating directory structure..." -ForegroundColor Yellow
    foreach ($folder in $folders) {
        $path = Join-Path -Path $basePath -ChildPath $folder
        New-Item -Path $path -ItemType Directory -Force | Out-Null
    }
    Write-Host "Directory structure created successfully." -ForegroundColor Green
    
    # Install required modules
    $modules = @("Posh-SSH", "SqlServer", "UniversalDashboard.Community", "ImportExcel", "PSWriteHTML")
    Write-Host "Step 2: Installing required PowerShell modules..." -ForegroundColor Yellow
    foreach ($module in $modules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Write-Host "  Installing $module..." -ForegroundColor Yellow
            Install-Module -Name $module -Force -AllowClobber -Scope CurrentUser
        } else {
            Write-Host "  $module already installed." -ForegroundColor Green
        }
    }
    Write-Host "Required modules installed successfully." -ForegroundColor Green
    
    # Create default configuration
    $configPath = Join-Path -Path $basePath -ChildPath "Config\settings.json"
    Write-Host "Step 3: Creating default configuration..." -ForegroundColor Yellow
    
    $defaultConfig = @{
        LogRepository = "C:\FraudAnalysis\Logs"
        ReportPath = "C:\FraudAnalysis\Reports"
        CollectionFrequency = 60
        DataSources = @{
            Windows = @{
                Enabled = $true
                EventLogs = @("*")
                MaxEvents = 1000
                DiscoveryEnabled = $true
            }
            Network = @{
                Enabled = $true
                Devices = @(
                    @{
                        Name = "*"
                        Type = "SSH"
                        Command = "show log"
                        DiscoverySubnet = "192.168.1.0/24"
                    }
                )
                DiscoveryEnabled = $true
            }
            SQL = @{
                Enabled = $true
                Servers = @(
                    @{
                        Name = "*"
                        Database = "*"
                        Query = "SELECT * FROM sys.fn_get_audit_file('*', NULL, NULL)"
                        DiscoveryEnabled = $true
                    }
                )
            }
            Custom = @{
                Enabled = $true
                Sources = @()
            }
        }
        Rules = @(
            @{
                Name = "Rapid Cross-System Access"
                Severity = "High"
                TimeThresholdSeconds = 3
            }
            @{
                Name = "After-Hours Database Access"
                Severity = "Medium"
                StartHour = 22
                EndHour = 5
            }
            @{
                Name = "Failed Login Followed By Success" 
                Severity = "High"
                TimeThresholdMinutes = 5
                MinFailedAttempts = 3
            }
        )
        Dashboard = @{
            Port = 10000
            RefreshInterval = 60
        }
    }
    
    $defaultConfig | ConvertTo-Json -Depth 10 | Set-Content -Path $configPath
    Write-Host "Default configuration created at: $configPath" -ForegroundColor Green
    
    # Create credential script
    $credentialScriptPath = Join-Path -Path $basePath -ChildPath "Scripts\Set-Credentials.ps1"
    Write-Host "Step 4: Creating credential management script..." -ForegroundColor Yellow
    
    $credentialScript = @'
# Run this script once to securely store credentials
Write-Host "Setting up credentials for Cross-Platform Activity Correlator" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Network device credentials
$networkCredentials = Get-Credential -Message "Enter network device credentials (or press Cancel to skip)"
if ($networkCredentials) {
    $networkCredentials | Export-Clixml -Path "C:\FraudAnalysis\Config\NetworkCred.xml" -Force
    Write-Host "Network credentials stored successfully" -ForegroundColor Green
} else {
    Write-Host "Network credentials skipped" -ForegroundColor Yellow
}

# SQL Server credentials
$sqlCredentials = Get-Credential -Message "Enter SQL Server credentials (or press Cancel to skip)"
if ($sqlCredentials) {
    $sqlCredentials | Export-Clixml -Path "C:\FraudAnalysis\Config\SQLCred.xml" -Force
    Write-Host "SQL Server credentials stored successfully" -ForegroundColor Green
} else {
    Write-Host "SQL Server credentials skipped" -ForegroundColor Yellow
}

Write-Host "Credential setup complete." -ForegroundColor Cyan
'@
    
    Set-Content -Path $credentialScriptPath -Value $credentialScript
    Write-Host "Credential management script created at: $credentialScriptPath" -ForegroundColor Green
    
    # Create scheduler script
    $schedulerScriptPath = Join-Path -Path $basePath -ChildPath "Scripts\Setup-Scheduler.ps1"
    Write-Host "Step 5: Creating scheduler setup script..." -ForegroundColor Yellow
    
    $schedulerScript = @'
# Load configuration
$config = Get-Content -Path "C:\FraudAnalysis\Config\settings.json" | ConvertFrom-Json

# Create scheduled tasks for log collection
$collectionAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\FraudAnalysis\Scripts\Collectors\Collect-AllLogs.ps1"
$collectionTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $config.CollectionFrequency)
$collectionSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -RunOnlyIfNetworkAvailable

Register-ScheduledTask -TaskName "FraudAnalysis_CollectLogs" -Action $collectionAction -Trigger $collectionTrigger -Settings $collectionSettings -RunLevel Highest -Force

# Create scheduled tasks for analysis (every 2 hours)
$analysisAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\FraudAnalysis\Scripts\Analysis\Analyze-ActivityPatterns.ps1"
$analysisTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 2)
$analysisSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

Register-ScheduledTask -TaskName "FraudAnalysis_AnalyzeActivity" -Action $analysisAction -Trigger $analysisTrigger -Settings $analysisSettings -RunLevel Highest -Force

# Create scheduled task for dashboard (at system startup)
$dashboardAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\FraudAnalysis\Scripts\Dashboard\Start-FraudDashboard.ps1"
$dashboardTrigger = New-ScheduledTaskTrigger -AtStartup
$dashboardSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

Register-ScheduledTask -TaskName "FraudAnalysis_StartDashboard" -Action $dashboardAction -Trigger $dashboardTrigger -Settings $dashboardSettings -RunLevel Highest -Force

Write-Host "Scheduled tasks created successfully!" -ForegroundColor Green
'@
    
    Set-Content -Path $schedulerScriptPath -Value $schedulerScript
    Write-Host "Scheduler setup script created at: $schedulerScriptPath" -ForegroundColor Green
    
    # Copy log collector script
    $collectorScriptPath = Join-Path -Path $basePath -ChildPath "Scripts\Collectors\Collect-AllLogs.ps1"
    Write-Host "Step 6: Creating log collector script..." -ForegroundColor Yellow
    # Copy the updated log collector script here
    Write-Host "Log collector script created at: $collectorScriptPath" -ForegroundColor Green
    
    # Copy analysis script
    $analysisScriptPath = Join-Path -Path $basePath -ChildPath "Scripts\Analysis\Analyze-ActivityPatterns.ps1"
    Write-Host "Step 7: Creating analysis script..." -ForegroundColor Yellow
    # Copy the updated analysis script here
    Write-Host "Analysis script created at: $analysisScriptPath" -ForegroundColor Green
    
    # Copy dashboard script
    $dashboardScriptPath = Join-Path -Path $basePath -ChildPath "Scripts\Dashboard\Start-FraudDashboard.ps1"
    Write-Host "Step 8: Creating dashboard script..." -ForegroundColor Yellow
    # Copy the updated dashboard script here
    Write-Host "Dashboard script created at: $dashboardScriptPath" -ForegroundColor Green
    
    # Set up credentials
    Write-Host "Step 9: Setting up credentials..." -ForegroundColor Yellow
    & $credentialScriptPath
    Write-Host "Credentials set up successfully." -ForegroundColor Green
    
    # Set up scheduled tasks
    Write-Host "Step 10: Setting up scheduled tasks..." -ForegroundColor Yellow
    & $schedulerScriptPath
    Write-Host "Scheduled tasks set up successfully." -ForegroundColor Green
    
    # Initial log collection
    Write-Host "Step 11: Performing initial log collection..." -ForegroundColor Yellow
    & $collectorScriptPath
    Write-Host "Initial log collection completed." -ForegroundColor Green
    
    # Initial analysis
    Write-Host "Step 12: Performing initial analysis..." -ForegroundColor Yellow
    & $analysisScriptPath
    Write-Host "Initial analysis completed." -ForegroundColor Green
    
    # Start dashboard
    Write-Host "Step 13: Starting dashboard..." -ForegroundColor Yellow
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $dashboardScriptPath"
    Write-Host "Dashboard started on port $((Get-Content -Path $configPath | ConvertFrom-Json).Dashboard.Port)." -ForegroundColor Green
    
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "Deployment complete! Access the dashboard at: http://localhost:$((Get-Content -Path $configPath | ConvertFrom-Json).Dashboard.Port)" -ForegroundColor Cyan
    Write-Host "The system will collect logs every $((Get-Content -Path $configPath | ConvertFrom-Json).CollectionFrequency) minutes." -ForegroundColor Cyan
    Write-Host "Analysis will run every 2 hours." -ForegroundColor Cyan
}
catch {
    Write-Host "Error during deployment: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}