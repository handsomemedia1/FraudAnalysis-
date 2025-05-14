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
