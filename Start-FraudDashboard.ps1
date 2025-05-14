# Load configuration
$configPath = "C:\FraudAnalysis\Config\settings.json"
if (Test-Path $configPath) {
    try {
        $config = Get-Content -Path $configPath -Raw | ConvertFrom-Json
    } catch {
        Write-Error "Error parsing configuration file: $_"
        exit 1
    }
} else {
        Write-Error "Configuration file not found at $configPath"
        exit 1
}

$logRepository = $config.LogRepository
$reportPath = $config.ReportPath
$port = 10000

# Create HTTP listener
try {
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$port/")
    $listener.Start()
} catch {
    Write-Error "Failed to start HTTP listener: $_"
    exit 1
}

Write-Host "Dashboard running at http://localhost:$port/"
Write-Host "Press Ctrl+C to stop"

# Function to get log statistics
function Get-LogStatistics {
    $stats = @{
        TotalLogs = 0
        WindowsLogs = 0
        NetworkLogs = 0
        SQLLogs = 0
        CustomLogs = 0
        RecentActivity = 0
    }
    
    try {
        $windowsFiles = Get-ChildItem -Path "$logRepository\windows_*.csv" -ErrorAction SilentlyContinue
        $networkFiles = Get-ChildItem -Path "$logRepository\network_*.csv" -ErrorAction SilentlyContinue
        $sqlFiles = Get-ChildItem -Path "$logRepository\sql_*.csv" -ErrorAction SilentlyContinue
        $customFiles = Get-ChildItem -Path "$logRepository\custom_*.csv" -ErrorAction SilentlyContinue
        
        $stats.WindowsLogs = ($windowsFiles | Measure-Object).Count
        $stats.NetworkLogs = ($networkFiles | Measure-Object).Count
        $stats.SQLLogs = ($sqlFiles | Measure-Object).Count
        $stats.CustomLogs = ($customFiles | Measure-Object).Count
        $stats.TotalLogs = $stats.WindowsLogs + $stats.NetworkLogs + $stats.SQLLogs + $stats.CustomLogs
        
        # Count recent activity (last 24 hours)
        $recentFiles = @($windowsFiles) + @($networkFiles) + @($sqlFiles) + @($customFiles) | 
                      Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-24) }
        $stats.RecentActivity = ($recentFiles | Measure-Object).Count
    } catch {
        Write-Error "Error getting log statistics: $_"
    }
    
    return $stats
}

# Function to get alert summary
function Get-AlertSummary {
    $summary = @{
        TotalAlerts = 0
        HighSeverity = 0
        MediumSeverity = 0
        LowSeverity = 0
        RecentAlerts = 0
        LatestAlert = "None"
    }
    
    try {
        $alertFiles = Get-ChildItem -Path "$reportPath\FraudDetection_*.csv" -ErrorAction SilentlyContinue
        if ($alertFiles.Count -gt 0) {
            $latestFile = $alertFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            
            try {
                $alerts = Import-Csv -Path $latestFile.FullName
                $summary.TotalAlerts = ($alerts | Measure-Object).Count
                $summary.HighSeverity = ($alerts | Where-Object { $_.Severity -eq "High" } | Measure-Object).Count
                $summary.MediumSeverity = ($alerts | Where-Object { $_.Severity -eq "Medium" } | Measure-Object).Count
                $summary.LowSeverity = ($alerts | Where-Object { $_.Severity -eq "Low" } | Measure-Object).Count
                
                $recentAlerts = $alerts | Where-Object { 
                    try { [datetime]::Parse($_.Time) -gt (Get-Date).AddHours(-24) } 
                    catch { $false } 
                }
                $summary.RecentAlerts = ($recentAlerts | Measure-Object).Count
                
                if ($summary.TotalAlerts -gt 0) {
                    $latestAlert = $alerts | Sort-Object { try { [datetime]::Parse($_.Time) } catch { [datetime]::MinValue } } -Descending | Select-Object -First 1
                    $summary.LatestAlert = "$($latestAlert.RuleName) - $($latestAlert.Severity) ($($latestAlert.Time))"
                }
            } catch {
                Write-Error "Error processing alert file: $_"
            }
        }
    } catch {
        Write-Error "Error getting alert summary: $_"
    }
    
    return $summary
}

# Function to get system health
function Get-SystemHealth {
    $health = @{
        Status = "Healthy"
        DiskSpaceGB = 0
        LogsCollectorRunning = $false
        AnalysisRunning = $false
        LastAnalysis = "Unknown"
        ScheduledTasksActive = 0
    }
    
    try {
        # Check disk space
        $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if ($disk) {
            $health.DiskSpaceGB = [Math]::Round($disk.FreeSpace / 1GB, 2)
        }
        
        # Check if processes are running
        $collectorProcess = Get-Process -Name powershell -ErrorAction SilentlyContinue | 
                           Where-Object { $_.CommandLine -like "*Collect-AllLogs.ps1*" }
        $health.LogsCollectorRunning = ($null -ne $collectorProcess)
        
        $analysisProcess = Get-Process -Name powershell -ErrorAction SilentlyContinue | 
                          Where-Object { $_.CommandLine -like "*Analyze-ActivityPatterns.ps1*" }
        $health.AnalysisRunning = ($null -ne $analysisProcess)
        
        # Check last analysis
        $analysisFiles = Get-ChildItem -Path "$reportPath\FraudDetection_*.csv" -ErrorAction SilentlyContinue
        if ($analysisFiles.Count -gt 0) {
            $latestFile = $analysisFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            $health.LastAnalysis = $latestFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        # Check scheduled tasks
        try {
            $tasks = Get-ScheduledTask -TaskName "FraudAnalysis_*" -ErrorAction SilentlyContinue
            $activeTasks = $tasks | Where-Object { $_.State -eq "Ready" }
            $health.ScheduledTasksActive = ($activeTasks | Measure-Object).Count
        } catch {
            # Scheduled tasks might not be available on all systems
            $health.ScheduledTasksActive = -1
        }
        
        # Determine overall status
        if ($health.DiskSpaceGB -lt 1) {
            $health.Status = "Warning: Low disk space"
        }
        if ($health.ScheduledTasksActive -ne -1 -and $health.ScheduledTasksActive -lt 3) {
            $health.Status = "Warning: Some tasks not active"
        }
    } catch {
        Write-Error "Error getting system health: $_"
    }
    
    return $health
}

# Basic HTML template with enhanced features
$htmlTemplate = @"
<!DOCTYPE html>
<html>
<head>
    <title>Fraud Detection System</title>
    <meta http-equiv="refresh" content="30">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .card { border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 20px; background-color: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .button { background-color: #4CAF50; border: none; color: white; padding: 10px 20px; 
                 text-align: center; text-decoration: none; display: inline-block; 
                 font-size: 16px; margin: 4px 2px; cursor: pointer; border-radius: 5px; }
        .button.blue { background-color: #2196F3; }
        .button.orange { background-color: #FF9800; }
        h1 { color: #333; }
        h2 { color: #444; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 10px; }
        .stat-box { background-color: #e9f7ef; padding: 10px; border-radius: 5px; text-align: center; }
        .stat-box.highlight { background-color: #d4edda; }
        .stat-box.alert { background-color: #f8d7da; }
        .stat-box h3 { margin-top: 0; font-size: 14px; }
        .stat-box p { font-size: 24px; font-weight: bold; margin: 5px 0; }
        .alert-high { color: #721c24; }
        .alert-medium { color: #856404; }
        .alert-low { color: #0c5460; }
        .health-good { color: #155724; }
        .health-warning { color: #856404; }
        .footer { text-align: center; font-size: 12px; color: #777; margin-top: 20px; }
    </style>
</head>
<body>
    <h1>Fraud Detection System</h1>
    
    <div class="card">
        <h2>Fraud Detection Status</h2>
        <p>Cross-Platform Activity Correlator is monitoring for suspicious patterns</p>
        <a href="/runanalysis" class="button">Run Analysis</a>
        <a href="/collectlogs" class="button blue">Collect Logs</a>
        <a href="/viewreports" class="button orange">View Reports</a>
    </div>
    
    <div class="card">
        <h2>Alert Summary</h2>
        <div class="stat-grid">
            <div class="stat-box highlight">
                <h3>Total Alerts</h3>
                <p>{TOTAL_ALERTS}</p>
            </div>
            <div class="stat-box alert">
                <h3>High Severity</h3>
                <p class="alert-high">{HIGH_SEVERITY}</p>
            </div>
            <div class="stat-box">
                <h3>Medium Severity</h3>
                <p class="alert-medium">{MEDIUM_SEVERITY}</p>
            </div>
            <div class="stat-box">
                <h3>Low Severity</h3>
                <p class="alert-low">{LOW_SEVERITY}</p>
            </div>
            <div class="stat-box">
                <h3>Recent (24h)</h3>
                <p>{RECENT_ALERTS}</p>
            </div>
        </div>
        <p><strong>Latest Alert:</strong> {LATEST_ALERT}</p>
    </div>
    
    <div class="card">
        <h2>Log Statistics</h2>
        <div class="stat-grid">
            <div class="stat-box highlight">
                <h3>Total Log Files</h3>
                <p>{TOTAL_LOGS}</p>
            </div>
            <div class="stat-box">
                <h3>Windows Logs</h3>
                <p>{WINDOWS_LOGS}</p>
            </div>
            <div class="stat-box">
                <h3>Network Logs</h3>
                <p>{NETWORK_LOGS}</p>
            </div>
            <div class="stat-box">
                <h3>SQL Logs</h3>
                <p>{SQL_LOGS}</p>
            </div>
            <div class="stat-box">
                <h3>Custom Logs</h3>
                <p>{CUSTOM_LOGS}</p>
            </div>
            <div class="stat-box">
                <h3>24-hour Activity</h3>
                <p>{RECENT_ACTIVITY}</p>
            </div>
        </div>
    </div>
    
    <div class="card">
        <h2>System Health</h2>
        <div class="stat-grid">
            <div class="stat-box">
                <h3>Status</h3>
                <p class="{HEALTH_CLASS}">{HEALTH_STATUS}</p>
            </div>
            <div class="stat-box">
                <h3>Free Disk Space</h3>
                <p>{DISK_SPACE} GB</p>
            </div>
            <div class="stat-box">
                <h3>Collector</h3>
                <p>{COLLECTOR_STATUS}</p>
            </div>
            <div class="stat-box">
                <h3>Analysis</h3>
                <p>{ANALYSIS_STATUS}</p>
            </div>
            <div class="stat-box">
                <h3>Active Tasks</h3>
                <p>{ACTIVE_TASKS}</p>
            </div>
        </div>
    </div>
    
    <div class="card">
        <h2>System Information</h2>
        <p><strong>Log Repository:</strong> {LOG_REPOSITORY}</p>
        <p><strong>Report Path:</strong> {REPORT_PATH}</p>
        <p><strong>Last Analysis:</strong> {LAST_ANALYSIS}</p>
        <p><strong>Last Update:</strong> {LAST_UPDATE}</p>
    </div>
    
    <div class="footer">
        Cross-Platform Activity Correlator for Fraud Detection | Server Time: {SERVER_TIME}
    </div>
</body>
</html>
"@

# Main loop
try {
    while ($listener.IsListening) {
        $context = $null
        try {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            # Handle different URL paths
            switch ($request.Url.LocalPath) {
                "/runanalysis" {
                    try {
                        Start-Process powershell -ArgumentList "-File `"C:\FraudAnalysis\Scripts\Analysis\Analyze-ActivityPatterns.ps1`"" -NoNewWindow
                        $response.Redirect("http://localhost:$port/")
                    } catch {
                        $response.StatusCode = 500
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes("Failed to start analysis: $_")
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }
                    break
                }
                "/collectlogs" {
                    try {
                        Start-Process powershell -ArgumentList "-File `"C:\FraudAnalysis\Scripts\Collectors\Collect-AllLogs.ps1`"" -NoNewWindow
                        $response.Redirect("http://localhost:$port/")
                    } catch {
                        $response.StatusCode = 500
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes("Failed to start log collection: $_")
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }
                    break
                }
                "/viewreports" {
                    try {
                        Start-Process "explorer.exe" -ArgumentList "`"$reportPath`""
                        $response.Redirect("http://localhost:$port/")
                    } catch {
                        $response.StatusCode = 500
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes("Failed to open reports folder: $_")
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }
                    break
                }
                default {
                    # Get current statistics
                    $logStats = Get-LogStatistics
                    $alertSummary = Get-AlertSummary
                    $systemHealth = Get-SystemHealth
                    
                    # Replace placeholders in HTML template
                    $html = $htmlTemplate.Replace("{LOG_REPOSITORY}", $logRepository)
                    $html = $html.Replace("{REPORT_PATH}", $reportPath)
                    $html = $html.Replace("{LAST_UPDATE}", (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
                    $html = $html.Replace("{SERVER_TIME}", (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
                    
                    # Log statistics
                    $html = $html.Replace("{TOTAL_LOGS}", $logStats.TotalLogs)
                    $html = $html.Replace("{WINDOWS_LOGS}", $logStats.WindowsLogs)
                    $html = $html.Replace("{NETWORK_LOGS}", $logStats.NetworkLogs)
                    $html = $html.Replace("{SQL_LOGS}", $logStats.SQLLogs)
                    $html = $html.Replace("{CUSTOM_LOGS}", $logStats.CustomLogs)
                    $html = $html.Replace("{RECENT_ACTIVITY}", $logStats.RecentActivity)
                    
                    # Alert summary
                    $html = $html.Replace("{TOTAL_ALERTS}", $alertSummary.TotalAlerts)
                    $html = $html.Replace("{HIGH_SEVERITY}", $alertSummary.HighSeverity)
                    $html = $html.Replace("{MEDIUM_SEVERITY}", $alertSummary.MediumSeverity)
                    $html = $html.Replace("{LOW_SEVERITY}", $alertSummary.LowSeverity)
                    $html = $html.Replace("{RECENT_ALERTS}", $alertSummary.RecentAlerts)
                    $html = $html.Replace("{LATEST_ALERT}", [System.Web.HttpUtility]::HtmlEncode($alertSummary.LatestAlert))
                    
                    # System health - fixed the if statements by calculating the values first
                    $healthClass = if ($systemHealth.Status -eq "Healthy") { "health-good" } else { "health-warning" }
                    $collectorStatus = if ($systemHealth.LogsCollectorRunning) { "Running" } else { "Idle" }
                    $analysisStatus = if ($systemHealth.AnalysisRunning) { "Running" } else { "Idle" }

                    $html = $html.Replace("{HEALTH_CLASS}", $healthClass)
                    $html = $html.Replace("{HEALTH_STATUS}", $systemHealth.Status)
                    $html = $html.Replace("{DISK_SPACE}", $systemHealth.DiskSpaceGB)
                    $html = $html.Replace("{COLLECTOR_STATUS}", $collectorStatus)
                    $html = $html.Replace("{ANALYSIS_STATUS}", $analysisStatus)
                    $html = $html.Replace("{ACTIVE_TASKS}", $systemHealth.ScheduledTasksActive)
                    $html = $html.Replace("{LAST_ANALYSIS}", $systemHealth.LastAnalysis)
                    
                    # Send response
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($html)
                    $response.ContentLength64 = $buffer.Length
                    $response.ContentType = "text/html"
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
            }
        } catch {
            Write-Error "Error processing request: $_"
            if ($null -ne $context) {
                try {
                    $context.Response.StatusCode = 500
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes("Internal server error")
                    $context.Response.ContentLength64 = $buffer.Length
                    $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
                } catch {
                    Write-Error "Failed to send error response: $_"
                }
            }
        } finally {
            if ($null -ne $context) {
                $context.Response.Close()
            }
        }
    }
} catch {
    Write-Error "Listener error: $_"
} finally {
    $listener.Stop()
    $listener.Close()
}
