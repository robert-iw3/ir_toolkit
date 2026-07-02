# Email alert script for monitoring
param([string]$Recipient = "admin@company.com")
$SmtpServer = "smtp.office365.com"
$SmtpPort   = 587
$From       = "monitor@company.com"
$Subject    = "Alert: Disk space low"
$Body       = "Disk space on $env:COMPUTERNAME is below 10%"
Send-MailMessage -To $Recipient -From $From -Subject $Subject `
    -Body $Body -SmtpServer $SmtpServer -Port $SmtpPort -UseSsl
