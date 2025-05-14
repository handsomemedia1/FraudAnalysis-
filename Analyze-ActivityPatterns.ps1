# Load configuration
$config = Get-Content -Path "C:\FraudAnalysis\Config\settings.json" | ConvertFrom-Json
$logRepository = $config.LogRepository
$reportPath = $config.ReportPath

# Create report directory if it doesn't exist
if (-not (Test-Path $reportPath)) {
    New-Item -Path $reportPath -ItemType Directory -Force | Out-Null
}

# Get latest log files for each source type
function Get-LatestLogs {
    # Windows logs
    $windowsLogs = @()
    $latestWindowsFiles = Get-ChildItem "$logRepository\windows_*_*.csv" -ErrorAction SilentlyContinue | 
                          Sort-Object LastWriteTime -Descending
    
    foreach ($file in $latestWindowsFiles) {
        try {
            $logs = Import-Csv $file.FullName
            $windowsLogs += $logs
        } catch {
            $errorMsg = $_
            Write-Warning ("Error importing {0} - {1}" -f $file.FullName, $errorMsg)
        }
    }
    
    # Network logs
    $networkLogs = @()
    $latestNetworkFiles = Get-ChildItem "$logRepository\network_*_*.csv" -ErrorAction SilentlyContinue | 
                          Sort-Object LastWriteTime -Descending
    
    foreach ($file in $latestNetworkFiles) {
        try {
            $logs = Import-Csv $file.FullName
            $networkLogs += $logs
        } catch {
            $errorMsg = $_
            Write-Warning ("Error importing {0} - {1}" -f $file.FullName, $errorMsg)
        }
    }
    
    # SQL logs
    $sqlLogs = @()
    $latestSQLFiles = Get-ChildItem "$logRepository\sql_*_*.csv" -ErrorAction SilentlyContinue | 
                      Sort-Object LastWriteTime -Descending
    
    foreach ($file in $latestSQLFiles) {
        try {
            $logs = Import-Csv $file.FullName
            $sqlLogs += $logs
        } catch {
            $errorMsg = $_
            Write-Warning ("Error importing {0} - {1}" -f $file.FullName, $errorMsg)
        }
    }
    
    # Custom logs
    $customLogs = @()
    $latestCustomFiles = Get-ChildItem "$logRepository\custom_*_*.csv" -ErrorAction SilentlyContinue | 
                         Sort-Object LastWriteTime -Descending
    
    foreach ($file in $latestCustomFiles) {
        try {
            $logs = Import-Csv $file.FullName
            $customLogs += $logs
        } catch {
            $errorMsg = $_
            Write-Warning ("Error importing {0} - {1}" -f $file.FullName, $errorMsg)
        }
    }
    
    # Return all logs
    return @{
        Windows = $windowsLogs
        Network = $networkLogs
        SQL = $sqlLogs
        Custom = $customLogs
    }
}

# Normalize log format for unified processing
function Convert-LogFormat {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Logs,
        
        [Parameter(Mandatory=$true)]
        [string]$LogType
    )
    
    $normalizedLogs = @()
    
    switch ($LogType) {
        "Windows" {
            $normalizedLogs = $Logs | ForEach-Object {
                $timeField = if ($_.TimeCreated) { $_.TimeCreated } else { Get-Date }
                
                try {
                    $time = [datetime]$timeField
                } catch {
                    $time = Get-Date
                }
                
                [PSCustomObject]@{
                    Time = $time
                    User = if ($_.User) { $_.User } else { "SYSTEM" }
                    Activity = if ($_.Id) { $_.Id } else { "Unknown" }
                    Details = if ($_.Message) { $_.Message } else { "No details" }
                    Source = "Windows"
                    SourceName = if ($_.Source) { $_.Source } else { "EventLog" }
                }
            }
        }
        "Network" {
            $normalizedLogs = $Logs | ForEach-Object {
                $timeField = if ($_.Time) { $_.Time } else { Get-Date }
                
                try {
                    $time = [datetime]$timeField
                } catch {
                    $time = Get-Date
                }
                
                # Extract user from message if possible
                $user = if ($_.User) { 
                    $_.User 
                } elseif ($_.Message -match "user (\w+)") {
                    $matches[1]
                } else {
                    "unknown"
                }
                
                [PSCustomObject]@{
                    Time = $time
                    User = $user
                    Activity = "NetworkActivity"
                    Details = if ($_.Message) { $_.Message } else { "No details" }
                    Source = "Network"
                    SourceName = if ($_.Device) { $_.Device } else { "Unknown" }
                }
            }
        }
        "SQL" {
            $normalizedLogs = $Logs | ForEach-Object {
                # Handle different field names from different SQL sources
                $timeField = if ($_.event_time) { 
                    $_.event_time 
                } elseif ($_.Time) {
                    $_.Time
                } else {
                    Get-Date
                }
                
                try {
                    $time = [datetime]$timeField
                } catch {
                    $time = Get-Date
                }
                
                $user = if ($_.server_principal_name) {
                    $_.server_principal_name
                } elseif ($_.User) {
                    $_.User
                } else {
                    "unknown"
                }
                
                $activity = if ($_.action_id) {
                    $_.action_id
                } elseif ($_.Activity) {
                    $_.Activity
                } else {
                    "DatabaseAccess"
                }
                
                $details = if ($_.statement) {
                    $_.statement
                } elseif ($_.Details) {
                    $_.Details
                } else {
                    "SQL Activity"
                }
                
                [PSCustomObject]@{
                    Time = $time
                    User = $user
                    Activity = $activity
                    Details = $details
                    Source = "SQL"
                    SourceName = if ($_.SourceName) { $_.SourceName } else { "Database" }
                }
            }
        }
        "Custom" {
            $normalizedLogs = $Logs | ForEach-Object {
                $timeField = if ($_.Time) { $_.Time } else { Get-Date }
                
                try {
                    $time = [datetime]$timeField
                } catch {
                    $time = Get-Date
                }
                
                [PSCustomObject]@{
                    Time = $time
                    User = if ($_.User) { $_.User } else { "unknown" }
                    Activity = if ($_.Activity) { $_.Activity } else { "CustomActivity" }
                    Details = if ($_.Message) { $_.Message } else { "No details" }
                    Source = "Custom"
                    SourceName = if ($_.SourceName) { $_.SourceName } else { "CustomSource" }
                }
            }
        }
    }
    
    return $normalizedLogs
}

# Temporal pattern analysis with flexible handling of different log formats
function Find-SuspiciousPatterns {
    param (
        [Parameter(Mandatory=$true)]
        [array]$NormalizedLogs
    )
    
    # Sort logs chronologically
    $sortedLogs = $NormalizedLogs | Sort-Object Time
    
    # Group by user
    $userGroups = $sortedLogs | Group-Object User
    
    $suspiciousPatterns = @()
    
    foreach ($userGroup in $userGroups) {
        $user = $userGroup.Name
        
        # Skip system or empty users
        if ($user -eq "SYSTEM" -or $user -eq "" -or $user -eq "unknown") { continue }
        
        $activities = $userGroup.Group | Sort-Object Time
        
        # Skip users with only one activity
        if ($activities.Count -lt 2) { continue }
        
        # Check for suspicious patterns
        for ($i = 0; $i -lt $activities.Count - 1; $i++) {
            $current = $activities[$i]
            $next = $activities[$i+1]
            
            $timeDiff = ($next.Time - $current.Time).TotalSeconds
            $sourceDiff = $current.Source -ne $next.Source
            
            # Suspicious if activities happen across different systems in short time
            if ($sourceDiff) {
                $suspiciousPatterns += [PSCustomObject]@{
                    User = $user
                    Time1 = $current.Time
                    Activity1 = $current.Activity
                    Details1 = $current.Details
                    Source1 = $current.Source
                    SourceName1 = $current.SourceName
                    Time2 = $next.Time
                    Activity2 = $next.Activity
                    Details2 = $next.Details
                    Source2 = $next.Source
                    SourceName2 = $next.SourceName
                    TimeDifference = $timeDiff
                }
            }
        }
    }
    
    return $suspiciousPatterns
}

# Apply detection rules with enhanced flexibility
function Test-FraudRules {
    param (
        [Parameter(Mandatory=$true)]
        [array]$SuspiciousData,
        
        [Parameter(Mandatory=$true)]
        [array]$AllLogs
    )
    
    $results = @()
    
    # Rule 1: Rapid Cross-System Access
    foreach ($entry in $SuspiciousData) {
        if ($entry.TimeDifference -lt $config.Rules[0].TimeThresholdSeconds) {
            $results += [PSCustomObject]@{
                User = $entry.User
                RuleName = $config.Rules[0].Name
                Severity = $config.Rules[0].Severity
                Time = $entry.Time2
                Details = ("Activity on {0} followed by activity on {1} in {2} seconds" -f $entry.Source1, $entry.Source2, $entry.TimeDifference)
                SourceDetails = ("First system: {0}, Second system: {1}" -f $entry.SourceName1, $entry.SourceName2)
            }
        }
    }
    
    # Rule 2: After-Hours Database Access
    $sqlLogs = $AllLogs | Where-Object { $_.Source -eq 'SQL' }
    foreach ($entry in $sqlLogs) {
        $hour = $entry.Time.Hour
        
        if ($hour -ge $config.Rules[1].StartHour -or $hour -le $config.Rules[1].EndHour) {
            $results += [PSCustomObject]@{
                User = $entry.User
                RuleName = $config.Rules[1].Name
                Severity = $config.Rules[1].Severity
                Time = $entry.Time
                Details = ("After-hours database activity detected at {0}" -f $entry.Time)
                SourceDetails = ("Database: {0}" -f $entry.SourceName)
            }
        }
    }
    
    # Rule 3: Failed Login Followed By Success
    $windowsLogs = $AllLogs | Where-Object { $_.Source -eq 'Windows' }
    $userGroups = $windowsLogs | Group-Object User
    
    foreach ($userGroup in $userGroups) {
        $user = $userGroup.Name
        
        # Skip system or empty users
        if ($user -eq "SYSTEM" -or $user -eq "" -or $user -eq "unknown") { continue }
        
        $activities = $userGroup.Group | Sort-Object Time
        
        # Find failed login events
        $failedLogins = $activities | Where-Object { 
            $_.Activity -eq "4625" -or # Failed login
            $_.Details -match "failed login" -or
            $_.Details -match "login failed" -or
            $_.Details -match "access denied"
        }
        
        # Find successful login events
        $successLogins = $activities | Where-Object { 
            $_.Activity -eq "4624" -or # Successful login
            $_.Details -match "logged on" -or
            $_.Details -match "login successful" -or
            $_.Details -match "access granted"
        }
        
        # Check for failed logins followed by success within threshold
        foreach ($successLogin in $successLogins) {
            $recentFailures = $failedLogins | Where-Object { 
                ($successLogin.Time - $_.Time).TotalMinutes -le $config.Rules[2].TimeThresholdMinutes -and
                $_.Time -lt $successLogin.Time
            }
            
            if ($recentFailures.Count -ge $config.Rules[2].MinFailedAttempts) {
                $results += [PSCustomObject]@{
                    User = $user
                    RuleName = $config.Rules[2].Name
                    Severity = $config.Rules[2].Severity
                    Time = $successLogin.Time
                    Details = ("{0} failed login attempts followed by successful login" -f $recentFailures.Count)
                    SourceDetails = ("Successful login at {0}" -f $successLogin.Time)
                }
            }
        }
    }
    
    return $results
}

# Generate enhanced report with support for different report formats
function New-FraudReport {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Alerts
    )
    
    # Create timestamp for report files
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmm'
    
    # Export to Excel
    $excelReport = "$reportPath\FraudDetection_$timestamp.xlsx"
    
    try {
        $Alerts | Export-Excel -Path $excelReport -WorksheetName "Alerts" -AutoSize -TableName "FraudAlerts" -FreezeTopRow -BoldTopRow
        
        # Add summary worksheet
        $severitySummary = $Alerts | Group-Object Severity | Select-Object Name, Count
        $ruleSummary = $Alerts | Group-Object RuleName | Select-Object Name, Count
        
        $severitySummary | Export-Excel -Path $excelReport -WorksheetName "Summary" -AutoSize -TableName "SeveritySummary" -StartRow 1 -StartColumn 1
        $ruleSummary | Export-Excel -Path $excelReport -WorksheetName "Summary" -AutoSize -TableName "RuleSummary" -StartRow 1 -StartColumn 4
        
        Write-Host "Excel report saved to: $excelReport" -ForegroundColor Green
    } catch {
        $errorMsg = $_
        Write-Warning ("Error creating Excel report - {0}" -f $errorMsg)
    }
    
    # Generate CSV report (simpler format for compatibility)
    $csvReport = "$reportPath\FraudDetection_$timestamp.csv"
    
    try {
        $Alerts | Export-Csv -Path $csvReport -NoTypeInformation
        Write-Host "CSV report saved to: $csvReport" -ForegroundColor Green
    } catch {
        $errorMsg = $_
        Write-Warning ("Error creating CSV report - {0}" -f $errorMsg)
    }
    
    return @{
        ExcelReport = $excelReport
        CsvReport = $csvReport
    }
}

# Main execution with enhanced error handling
try {
    Write-Host "Starting activity analysis at $(Get-Date)" -ForegroundColor Cyan
    
    # Get logs from all sources
    $logs = Get-LatestLogs
    
    $totalLogs = ($logs.Windows.Count + $logs.Network.Count + $logs.SQL.Count + $logs.Custom.Count)
    Write-Host "Retrieved $totalLogs total log entries" -ForegroundColor Yellow
    Write-Host "  Windows: $($logs.Windows.Count)" -ForegroundColor Yellow
    Write-Host "  Network: $($logs.Network.Count)" -ForegroundColor Yellow
    Write-Host "  SQL: $($logs.SQL.Count)" -ForegroundColor Yellow
    Write-Host "  Custom: $($logs.Custom.Count)" -ForegroundColor Yellow
    
    # Normalize all logs
$normalizedLogs = @()
if ($logs.Windows.Count -gt 0) { $normalizedLogs += Convert-LogFormat -Logs $logs.Windows -LogType "Windows" }
if ($logs.Network.Count -gt 0) { $normalizedLogs += Convert-LogFormat -Logs $logs.Network -LogType "Network" }
if ($logs.SQL.Count -gt 0) { $normalizedLogs += Convert-LogFormat -Logs $logs.SQL -LogType "SQL" }
if ($logs.Custom.Count -gt 0) { $normalizedLogs += Convert-LogFormat -Logs $logs.Custom -LogType "Custom" }
    Write-Host "Normalized $($normalizedLogs.Count) log entries" -ForegroundColor Yellow
    # Find suspicious patterns
    $suspicious = Find-SuspiciousPatterns -NormalizedLogs $normalizedLogs
    Write-Host "Found $($suspicious.Count) suspicious patterns" -ForegroundColor Yellow
    
    # Apply rules
    $alerts = Test-FraudRules -SuspiciousData $suspicious -AllLogs $normalizedLogs
    Write-Host "Generated $($alerts.Count) alerts" -ForegroundColor Yellow
    
    # Create report if there are alerts
    if ($alerts.Count -gt 0) {
        $reports = New-FraudReport -Alerts $alerts
        Write-Host "Excel Report Path: $($reports.ExcelReport)" -ForegroundColor Green
        Write-Host "CSV Report Path: $($reports.CsvReport)" -ForegroundColor Green
        Write-Host "Reports generated successfully" -ForegroundColor Green
    }
    else {
        Write-Host "No alerts generated. No report created." -ForegroundColor Green
    }
    
    Write-Host "Analysis completed at $(Get-Date)" -ForegroundColor Cyan
}
catch {
    $errorMsg = $_
    Write-Host ("Critical error in analysis - {0}" -f $errorMsg) -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
}
