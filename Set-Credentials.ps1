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
