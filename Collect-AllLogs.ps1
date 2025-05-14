# Load configuration
$config = Get-Content -Path "C:\FraudAnalysis\Config\settings.json" | ConvertFrom-Json
$logRepository = $config.LogRepository

# Load credentials
try {
    $networkCredentials = Import-Clixml -Path "C:\FraudAnalysis\Config\NetworkCred.xml"
    $sqlCredentials = Import-Clixml -Path "C:\FraudAnalysis\Config\SQLCred.xml"
} catch {
    $errorMsg = $_
    Write-Warning ("Credentials not found. Some features may not work. Error: {0}" -f $errorMsg)
}

# Function to discover Windows event logs
function Get-AvailableEventLogs {
    try {
        $availableLogs = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | 
                          Where-Object { $_.RecordCount -gt 0 -and $_.IsEnabled } | 
                          Select-Object -ExpandProperty LogName
        return $availableLogs
    } catch {
        $errorMsg = $_
        Write-Warning ("Error discovering event logs: {0}" -f $errorMsg)
        return @("Security", "System", "Application")
    }
}

# Function to discover network devices
function Get-AvailableNetworkDevices {
    param(
        [string]$Subnet = "192.168.1.0/24"
    )
    
    try {
        # Extract subnet base and mask
        $subnetBase = $Subnet.Split('/')[0]
        # Removed unused variable $subnetMask
        
        $subnetBase = $subnetBase.Substring(0, $subnetBase.LastIndexOf('.') + 1)
        
        $availableDevices = @()
        
        for ($i = 1; $i -lt 255; $i++) {
            $ip = "$subnetBase$i"
            
            # Test connection with timeout
            $result = Test-Connection -ComputerName $ip -Count 1 -Quiet -TimeoutSeconds 1
            
            if ($result) {
                try {
                    $hostname = [System.Net.Dns]::GetHostByAddress($ip).HostName
                } catch {
                    $hostname = $ip
                }
                
                $availableDevices += [PSCustomObject]@{
                    Name = $hostname
                    IP = $ip
                    Type = "SSH" # Default to SSH
                }
            }
        }
        
        return $availableDevices
    } catch {
        $errorMsg = $_
        Write-Warning ("Error discovering network devices: {0}" -f $errorMsg)
        return @()
    }
}

# Function to discover SQL servers
function Get-AvailableSQLServers {
    try {
        $registeredServers = @()
        
        # Method 1: Try using SQL Server cmdlets if available
        if (Get-Command Get-SqlInstance -ErrorAction SilentlyContinue) {
            $registeredServers = Get-SqlInstance | Select-Object -ExpandProperty Name
        }
        # Method 2: Try using WMI
        else {
            $registeredServers = Get-WmiObject -Namespace "root\Microsoft\SqlServer\ComputerManagement14" -Class SqlService -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName -like "*SQL Server (*" } |
                ForEach-Object { $env:COMPUTERNAME }
        }
        
        if ($registeredServers.Count -eq 0) {
            # Default to local if nothing found
            $registeredServers = @($env:COMPUTERNAME)
        }
        
        return $registeredServers | ForEach-Object {
            [PSCustomObject]@{
                Name = $_
                Database = "master"
            }
        }
    } catch {
        $errorMsg = $_
        Write-Warning ("Error discovering SQL servers: {0}" -f $errorMsg)
        return @()
    }
}

# Function to get all databases on a SQL server
function Get-SQLDatabases {
    param(
        [string]$ServerName
    )
    
    try {
        $query = "SELECT name FROM sys.databases WHERE database_id > 4" # Skip system databases
        $databases = Invoke-Sqlcmd -ServerInstance $ServerName -Database "master" -Query $query -Credential $sqlCredentials -ErrorAction Stop
        return $databases.name
    } catch {
        $errorMsg = $_
        Write-Warning ("Error getting databases from {0} - {1}" -f $ServerName, $errorMsg)
        return @("master")
    }
}

# Windows Event Log collection
function Get-WindowsSecurityLogs {
    if ($config.DataSources.Windows.Enabled) {
        $logNames = $config.DataSources.Windows.EventLogs
        
        # Handle wildcard configuration
        if ($logNames -contains "*" -or $config.DataSources.Windows.DiscoveryEnabled) {
            $logNames = Get-AvailableEventLogs
            Write-Host "Discovered $(($logNames | Measure-Object).Count) event logs"
        }
        
        foreach ($logName in $logNames) {
            $fileName = "$logRepository\windows_$($logName.Replace('/', '-').Replace('\', '-').ToLower())_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
            Write-Host "Collecting $logName logs..."
            
            try {
                Get-WinEvent -LogName $logName -MaxEvents $config.DataSources.Windows.MaxEvents -ErrorAction SilentlyContinue | 
                    Select-Object TimeCreated, Id, LevelDisplayName, Message, 
                        @{Name='User';Expression={
                            if ($_.Properties.Count -gt 1) { $_.Properties[1].Value } else { "SYSTEM" }
                        }},
                        @{Name='Source';Expression={'Windows'}} |
                    Export-Csv $fileName -NoTypeInformation
                
                Write-Host "  Saved to $fileName" -ForegroundColor Green
            }
            catch {
                $errorMsg = $_
                Write-Host ("Error collecting {0} logs - {1}" -f $logName, $errorMsg) -ForegroundColor Red
            }
        }
    }
}

# Network device logs
function Get-NetworkDeviceLogs {
    if ($config.DataSources.Network.Enabled) {
        $devices = $config.DataSources.Network.Devices
        
        # Handle wildcard configuration
        if (($devices.Name -contains "*" -or $config.DataSources.Network.DiscoveryEnabled) -and $devices.Count -gt 0) {
            $subnet = $devices[0].DiscoverySubnet
            $devices = Get-AvailableNetworkDevices -Subnet $subnet
            Write-Host "Discovered $(($devices | Measure-Object).Count) network devices"
        }
        
        foreach ($device in $devices) {
            $fileName = "$logRepository\network_$($device.Name.Replace('.', '_'))_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
            Write-Host "Collecting logs from $($device.Name)..."
            
            try {
                # First check if we can connect
                $canConnect = Test-NetConnection -ComputerName $device.Name -Port 22 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
                
                if ($canConnect) {
                    $session = New-SSHSession -ComputerName $device.Name -Credential $networkCredentials -ErrorAction Stop
                    $command = if ($device.Command) { $device.Command } else { "show log" }
                    $result = Invoke-SSHCommand -SessionId $session.SessionId -Command $command -ErrorAction Stop
                    
                    # Process logs and add timestamp
                    $processedLogs = foreach ($line in $result.Output) {
                        [PSCustomObject]@{
                            Time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                            Device = $device.Name
                            Message = $line
                            Source = 'Network'
                        }
                    }
                    
                    $processedLogs | Export-Csv $fileName -NoTypeInformation
                    Remove-SSHSession -SessionId $session.SessionId -ErrorAction SilentlyContinue
                    
                    Write-Host "  Saved to $fileName" -ForegroundColor Green
                } else {
                    Write-Host "  Cannot connect to $($device.Name) on port 22" -ForegroundColor Yellow
                    
                    # Try to collect logs using WinRM as fallback
                    if (Test-WSMan -ComputerName $device.Name -ErrorAction SilentlyContinue) {
                        Write-Host "  Trying WinRM connection..." -ForegroundColor Yellow
                        $logs = Invoke-Command -ComputerName $device.Name -ScriptBlock {
                            Get-EventLog -LogName System -Newest 100 | Select-Object TimeGenerated, EntryType, Source, Message
                        } -Credential $networkCredentials -ErrorAction Stop
                        
                        $processedLogs = foreach ($log in $logs) {
                            [PSCustomObject]@{
                                Time = $log.TimeGenerated.ToString('yyyy-MM-dd HH:mm:ss')
                                Device = $device.Name
                                Message = $log.Message
                                Source = 'Network'
                            }
                        }
                        
                        $processedLogs | Export-Csv $fileName -NoTypeInformation
                        Write-Host "  Saved to $fileName (via WinRM)" -ForegroundColor Green
                    } else {
                        Write-Host "  Cannot connect to $($device.Name) via WinRM either" -ForegroundColor Red
                    }
                }
            }
            catch {
                $errorMsg = $_
                Write-Host ("Error collecting logs from {0} - {1}" -f $device.Name, $errorMsg) -ForegroundColor Red
            }
        }
    }
}

# Application logs (SQL Server)
function Get-SQLServerLogs {
    if ($config.DataSources.SQL.Enabled) {
        $servers = $config.DataSources.SQL.Servers
        
        # Handle wildcard configuration
        if (($servers.Name -contains "*" -or $servers[0].DiscoveryEnabled) -and $servers.Count -gt 0) {
            $servers = Get-AvailableSQLServers
            Write-Host "Discovered $(($servers | Measure-Object).Count) SQL servers"
        }
        
        foreach ($server in $servers) {
            # Handle wildcard database configuration
            $databases = @($server.Database)
            
            if ($databases -contains "*") {
                $databases = Get-SQLDatabases -ServerName $server.Name
                Write-Host "Discovered $(($databases | Measure-Object).Count) databases on $($server.Name)"
            }
            
            foreach ($database in $databases) {
                $fileName = "$logRepository\sql_$($server.Name.Replace('.', '_'))_$($database.Replace('.', '_'))_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
                Write-Host "Collecting logs from SQL Server $($server.Name), database $database..."
                
                try {
                    # Adjust query based on database
                    $query = $server.Query
                    
                    if ($database -eq "master") {
                        # Use standard audit file query if available
                        $testQuery = "SELECT COUNT(*) AS FileCount FROM sys.fn_my_permissions(NULL, NULL) WHERE permission_name = 'CONTROL SERVER'"
                        $testResult = Invoke-Sqlcmd -ServerInstance $server.Name -Database $database -Query $testQuery -Credential $sqlCredentials -ErrorAction Stop
                        
                        if ($testResult.FileCount -gt 0) {
                            $query = "SELECT GETDATE() AS event_time, 
                                      SYSTEM_USER AS server_principal_name, 
                                      'Database Access' AS action_id, 
                                      'Query execution' AS statement,
                                      'SQL' AS Source"
                        }
                    } else {
                        # Use database-specific query
                        $query = "SELECT GETDATE() AS event_time, 
                                  SYSTEM_USER AS server_principal_name, 
                                  'Database Access' AS action_id, 
                                  'Query execution in $database' AS statement,
                                  'SQL' AS Source"
                    }
                    
                    Invoke-Sqlcmd -ServerInstance $server.Name -Database $database -Query $query -Credential $sqlCredentials -ErrorAction Stop | 
                        Export-Csv $fileName -NoTypeInformation
                    
                    Write-Host "  Saved to $fileName" -ForegroundColor Green
                }
                catch {
                    $errorMsg = $_
                    Write-Host ("Error collecting SQL logs from {0}, database {1} - {2}" -f $server.Name, $database, $errorMsg) -ForegroundColor Red
                }
            }
        }
    }
}

# Support for custom log sources
function Get-CustomSourceLogs {
    if ($config.DataSources.Custom.Enabled -and $config.DataSources.Custom.Sources) {
        foreach ($source in $config.DataSources.Custom.Sources) {
            $fileName = "$logRepository\custom_$($source.Name.Replace('.', '_'))_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
            Write-Host "Collecting logs from custom source $($source.Name)..."
            
            try {
                # Handle different types of custom sources
                switch ($source.Type) {
                    "File" {
                        $logs = Get-Content -Path $source.Path -ErrorAction Stop
                        $processedLogs = foreach ($line in $logs) {
                            [PSCustomObject]@{
                                Time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                Source = 'Custom'
                                SourceName = $source.Name
                                Message = $line
                            }
                        }
                        $processedLogs | Export-Csv $fileName -NoTypeInformation
                    }
                    "API" {
                        $response = Invoke-RestMethod -Uri $source.Url -Method $source.Method -Headers $source.Headers -ErrorAction Stop
                        $processedLogs = foreach ($item in $response) {
                            [PSCustomObject]@{
                                Time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                Source = 'Custom'
                                SourceName = $source.Name
                                Message = ($item | ConvertTo-Json -Compress)
                            }
                        }
                        $processedLogs | Export-Csv $fileName -NoTypeInformation
                    }
                    "Script" {
                        # Execute custom script
                        $scriptResult = & $source.ScriptPath
                        $processedLogs = foreach ($item in $scriptResult) {
                            [PSCustomObject]@{
                                Time = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
                                Source = 'Custom'
                                SourceName = $source.Name
                                Message = ($item | ConvertTo-Json -Compress)
                            }
                        }
                        $processedLogs | Export-Csv $fileName -NoTypeInformation
                    }
                    default {
                        Write-Warning ("Unknown custom source type: {0}" -f $source.Type)
                        continue
                    }
                }
                
                Write-Host "  Saved to $fileName" -ForegroundColor Green
            }
            catch {
                $errorMsg = $_
                Write-Host ("Error collecting logs from custom source {0} - {1}" -f $source.Name, $errorMsg) -ForegroundColor Red
            }
        }
    }
}

# Error handling wrapper
function Invoke-SafeCollection {
    param(
        [Parameter(Mandatory=$true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
    
    try {
        Write-Host "Starting $Name collection..." -ForegroundColor Cyan
        & $ScriptBlock
        Write-Host "$Name collection completed" -ForegroundColor Cyan
    }
    catch {
        $errorMsg = $_
        Write-Host ("Error in {0} collection - {1}" -f $Name, $errorMsg) -ForegroundColor Red
    }
}

# Main execution
Write-Host "Starting log collection at $(Get-Date)" -ForegroundColor Cyan

# Create log directory if it doesn't exist
if (-not (Test-Path $logRepository)) {
    New-Item -Path $logRepository -ItemType Directory -Force | Out-Null
}

# Collect logs from all sources with error handling
Invoke-SafeCollection -ScriptBlock { Get-WindowsSecurityLogs } -Name "Windows"
Invoke-SafeCollection -ScriptBlock { Get-NetworkDeviceLogs } -Name "Network"
Invoke-SafeCollection -ScriptBlock { Get-SQLServerLogs } -Name "SQL"
Invoke-SafeCollection -ScriptBlock { Get-CustomSourceLogs } -Name "Custom sources"

Write-Host "Log collection completed at $(Get-Date)" -ForegroundColor Cyan
