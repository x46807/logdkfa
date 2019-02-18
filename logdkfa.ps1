
param (  
[int]$time_period = 300,
[string]$config_path = ".\default.conf"
)

$loglist = "Security","System","Application","Microsoft-Windows-PowerShell/Operational"


#Configure the array to set audit policy settings
#Fields are as follows:  @("<category>","<subcategory>","<success>","<failure>")
#Use wildcards to apply settings globally for the parameter. 
#For example ("Account Logon","*","enable","disable"),
#applies all "Account logon" subcategories success events.
#Don't specify a category if specifying subcategories
#Defaults below are set to MS Audit Policy "Stronger Recommendations" best practices:
#https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/identity/ad-ds/plan/security-best-practices/Audit-Policy-Recommendations.md
#Future plan is to wrap this into a config file and upload different types of config files to the repo
$audit_settings = @(
    ,@("Account Logon","*","enable","enable")
	,@("","Computer Account Management","enable","enable")
	,@("","Other Account Management Events","enable","enable")
	,@("","Security Group Management","enable","enable")
	,@("","User Account MAnagement","enable","enable")
	,@("","DPAPI Activity","enable","enable")
	,@("","Process Creation","enable","enable")
	,@("","Account Lockout","enable","disable")
	,@("","Logoff","enable","disable")
	,@("","Logon","enable","enable")
	,@("","Special Logon","enable","enable")
	,@("","Audit Policy Change","enable","enable")
	,@("","Authentication Policy Change","enable","enable")
	,@("","MPSSVC Rule-Level Policy Change","enable","disable")
	,@("","IPsec Driver","enable","enable")
	,@("","Security State Change","enable","enable")
	,@("","Security System Extension","enable","enable")
	,@("","System Integrity","enable","enable")
	

)


#First, collect the current log configurations and store them in a temp file to restore later.  
#While log configurations are not changed by default, this allows for changing configs in the future.
$new_path = "$Env:Temp\logstor\"
If(!(test-path $new_path)){
New-Item $new_path -itemtype directory
}
foreach ($logname in $loglist) {
$command = @'
cmd.exe /C wevtutil.exe gl $logname /f:XML 
'@
#Replace / character in lognames with underscore _
$filename = $($logname -replace "\/", '_')

Invoke-Expression -Command:$command | out-file $new_path\$filename.xml
}
#Next, backup current audit policy settings and save to a temporary file
Invoke-Expression -Command "auditpol /backup /file:$new_path\audit_backup.csv"

foreach ($line in $audit_settings) {
if ($line[1] -eq "*") {

$subcategory = ""
} else {
$subcategory = '/subcategory:"{0}"' -f $line[1]
}
if ($line[0] -eq "") {
$category = ""
} else {
$category = '/category:"{0}"' -f $line[0]
}
Write-Host "Configuring audit settings for $category $subcategory"
$audit_config = 'auditpol /set {0} {1} /success:"{2}" /failure:"{3}" ' -f $category, $subcategory, $line[2], $line[3]

Invoke-Expression -Command:$audit_config
}

Write-Host "Custom audit settings enabled for $time_period seconds"
#Invoke sleep to allow logs to be collected for specified period of time
Start-Sleep -s $time_period

#Restore log configurations to original state
foreach ($logname in $loglist) {
#Replace / character in lognames with underscore _
$filename = $($logname -replace "\/", '_')
$command = @'
cmd.exe /C wevtutil.exe sl /c:$new_path\$filename 
'@
}
#Next, restore audit policy from backup
Invoke-Expression -Command "auditpol /restore /file:$new_path\audit_backup.csv"


#Clean up temp files
Remove-Item -path $new_path -recurse