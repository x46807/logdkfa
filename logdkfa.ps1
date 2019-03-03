
param (  
[int]$time_period = 300,
[string]$config_path = ".\conf.json"
)



function set_object_audit {
 param( [string]$object_path, 
 [string[]]$accounts, 
 [string[]]$auditrights, 
 [string[]]$inheritanceflags,
 [string[]]$propagationflags,
 [string[]]$auditflags,
 [string]$type)

<#
Example:  set_object_audit -object_path $env:userprofile\Desktop -accounts "Everyone" -auditrights "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes" -inheritanceflags "ContainerInherit, ObjectInherit" -propagationflags "NoPropagateInherit" -auditflags "Success" -type "file"
Example:  set_object_audit -object_path HKCU:\Software\Classes\CLSID -accounts "Everyone" -auditrights "SetValue,CreateSubkey,Delete,ChangePermissions,TakeOwnership" -inheritanceflags "ContainerInherit, ObjectInherit" -propagationflags "NoPropagateInherit" -auditflags "Success" -type "reg"
FileSystemRights Ref:  https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=netframework-4.7.2
InheritanceFlags Ref:  https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.inheritanceflags?view=netframework-4.7.2
PropagationFlags Ref: https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.propagationflags?view=netframework-4.7.2
AuditFlags Ref:  https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.auditflags?view=netframework-4.7.2
#>



if($type -eq "file") {
$ACL = new-object System.Security.AccessControl.DirectorySecurity
$AccessRule = new-object System.Security.AccessControl.FileSystemAuditRule($accounts, $auditrights, $inheritanceflags, $propagationflags, $auditflags)
}
elseif($type -eq "reg") {
$ACL = new-object System.Security.AccessControl.RegistrySecurity
$AccessRule = new-object System.Security.AccessControl.RegistryAuditRule($accounts, $auditrights, $inheritanceflags, $propagationflags, $auditflags)
}
$ACL.SetAuditRule($AccessRule)
$ACL | Set-Acl $object_path -ErrorAction SilentlyContinue

}

function remove_object_audit {
 param( [string]$object_path, 
 [string[]]$accounts, 
 [string[]]$auditrights, 
 [string[]]$inheritanceflags,
 [string[]]$propagationflags,
 [string[]]$auditflags,
 [string]$type)

<#
Example:  remove_object_audit -object_path $env:userprofile\Desktop -accounts "Everyone" -auditrights "AppendData, ChangePermissions, CreateDirectories, CreateFiles, Delete, DeleteSubdirectoriesAndFiles, TakeOwnership, Write, WriteAttributes, WriteExtendedAttributes" -inheritanceflags "ContainerInherit, ObjectInherit" -propagationflags "NoPropagateInherit" -auditflags "Success" -type "file"
FileSystemRights Ref:  https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights?view=netframework-4.7.2
InheritanceFlags Ref:  https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.inheritanceflags?view=netframework-4.7.2
PropagationFlags Ref: https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.propagationflags?view=netframework-4.7.2
AuditFlags Ref:  https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.auditflags?view=netframework-4.7.2
#>

if($type -eq "file") {
$ACL = new-object System.Security.AccessControl.DirectorySecurity
$AccessRule = new-object System.Security.AccessControl.FileSystemAuditRule($accounts, $auditrights, $inheritanceflags, $propagationflags, $auditflags)
}
elseif($type -eq "reg") {
$ACL = new-object System.Security.AccessControl.RegistrySecurity
$AccessRule = new-object System.Security.AccessControl.RegistryAuditRule($accounts, $auditrights, $inheritanceflags, $propagationflags, $auditflags)
}
$ACL.RemoveAuditRule($AccessRule)
$ACL | Set-Acl $object_path -ErrorAction SilentlyContinue

}

#Read from config file and convert to hash table
$conf = $(gc $config_path | convertfrom-json)

$loglist = "Security","System","Application","Microsoft-Windows-PowerShell/Operational"

<#
Configure the array to set audit policy settings
Fields are as follows:  @("<category>","<subcategory>","<success>","<failure>")
Use wildcards to apply settings globally for the parameter. 
For example ("Account Logon","*","enable","disable"),
applies all "Account logon" subcategories success events.
Don't specify a category if specifying subcategories
Defaults below are set to MS Audit Policy "Stronger Recommendations" best practices:
https://github.com/MicrosoftDocs/windowsserverdocs/blob/master/WindowsServerDocs/identity/ad-ds/plan/security-best-practices/Audit-Policy-Recommendations.md
Future plan is to wrap this into a config file and upload different types of config files to the repo
#>
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



<#
If configuration specifies that file auditing should be enabled, read from
the file audit configuration file and create auditing ACLs on the files of interest. 
#>
 
if($conf.file_auditing.enabled -eq "true") {
Write-Host ""
Write-Host "######################"
Write-Host "########################"
Write-Host "##########################"
Write-Host "########################"
Write-Host "######################"
Write-Host ""
Write-Host "Configuring filesystem auditing"
Write-Host ""
$file_conf = gc $conf.file_auditing.path
$audit_type = "file"
foreach ($line in $file_conf) {
if ($line.StartsWith("#"))
{}
elseif ($line.StartsWith("%")) {
$account_list = $line.split("%")[1]
$rights = $line.split("%")[2]
$inheritance = $line.split("%")[3]
$propagation = $line.split("%")[4]
$audit = $line.split("%")[5]
} 
elseif ($line.StartsWith("X")) {
$current_path = $line.Substring(1)
$error.clear()
try {
remove_object_audit -object_path $current_path -accounts $account_list -auditrights $rights -inheritanceflags $inheritance -propagationflags $propagation -auditflags $audit -type $audit_type
} catch {
"Error removing auditing on $current_path"
 }
if (!$error) {
Write-Host "Removed auditing for $current_path"
}
}
else {
$current_path = $line
$error.clear()
try {
set_object_audit -object_path $current_path -accounts $account_list -auditrights $rights -inheritanceflags $inheritance -propagationflags $propagation -auditflags $audit -type $audit_type
} catch {
"Error setting auditing on $current_path"
 }
if (!$error) {
Write-Host "Successfully set auditing for $current_path"
}
}
}
}


<#
If configuration specifies that registry auditing should be enabled, read from
the registry audit configuration file and create auditing ACLs on the registry keys of interest.
#>
 
if($conf.registry_auditing.enabled -eq "true") {
Write-Host ""
Write-Host "######################"
Write-Host "########################"
Write-Host "##########################"
Write-Host "########################"
Write-Host "######################"
Write-Host ""
Write-Host "Configuring registry auditing"
Write-Host ""
$reg_conf = gc $conf.registry_auditing.path
$audit_type = "reg"
#HKU is not registered as a PSDrive by default:
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue
#Extract SIDs for interactive users
$usersids = $(gci hku:).name | select-String -Pattern 'S-1-5-21' | select-String -notmatch "Classes"
foreach ($line in $reg_conf) {
if ($line.StartsWith("#"))
{}
elseif ($line.StartsWith("%")) {
$account_list = $line.split("%")[1]
$rights = $line.split("%")[2]
$inheritance = $line.split("%")[3]
$propagation = $line.split("%")[4]
$audit = $line.split("%")[5]
} 
elseif ($line.StartsWith("X")) 
{
$current_path = $line.Substring(1)
remove_object_audit -object_path $current_path -accounts $account_list -auditrights $rights -inheritanceflags $inheritance -propagationflags $propagation -auditflags $audit -type $audit_type
Write-Host "Removing auditing for $current_path"
}
elseif ($line.StartsWith("HKU:\<SID>")) 
{
$fragment_path = $line.Substring(10)
foreach ($sid in $usersids) {
$sid_value = $sid.tostring().substring(11)
$current_path = "HKU:\$sid_value$fragment_path"
$error.clear()
try {
set_object_audit -object_path $current_path -accounts $account_list -auditrights $rights -inheritanceflags $inheritance -propagationflags $propagation -auditflags $audit -type $audit_type
} catch {
"Error setting auditing on $current_path"
 }
if (!$error) {
Write-Host "Successfully set auditing for $current_path"
}
}
}
else {
$current_path = $line
$error.clear()
try {
set_object_audit -object_path $current_path -accounts $account_list -auditrights $rights -inheritanceflags $inheritance -propagationflags $propagation -auditflags $audit -type $audit_type
} catch {
"Error setting auditing on $current_path"
 }
if (!$error) {
Write-Host "Successfully set auditing for $current_path"
}
}

}
}


Write-Host "Custom audit settings enabled for $time_period seconds"
#Invoke sleep to allow logs to be collected for specified period of time
Start-Sleep -s $time_period
Write-Host ""
Write-Host "######################"
Write-Host "########################"
Write-Host "##########################"
Write-Host "########################"
Write-Host "######################"
Write-Host ""
Write-Host "Restoring original audit settings"

#Remove file and registry auditing, if configured:
if($conf.file_auditing.enabled -eq "true") {
$file_conf = gc $conf.file_auditing.path
$audit_type = "file"
foreach ($line in $file_conf) {
if (($line.StartsWith("#")) -or ($line.StartsWith("X")))
{}
elseif ($line.StartsWith("%")) {
$account_list = $line.split("%")[1]
$rights = $line.split("%")[2]
$inheritance = $line.split("%")[3]
$propagation = $line.split("%")[4]
$audit = $line.split("%")[5]
} 
else {
$current_path = $line
$error.clear()
try {
remove_object_audit -object_path $current_path -accounts $account_list -auditrights $rights -inheritanceflags $inheritance -propagationflags $propagation -auditflags $audit -type $audit_type
} catch {
"Error removing auditing on $current_path"
 }
if (!$error) {
Write-Host "Successfully removed auditing for $current_path"
}
}
}
}


if($conf.registry_auditing.enabled -eq "true") {
$reg_conf = gc $conf.registry_auditing.path
$audit_type = "reg"
foreach ($line in $reg_conf) {
if (($line.StartsWith("#")) -or ($line.StartsWith("X")))
{}
elseif ($line.StartsWith("%")) {
$account_list = $line.split("%")[1]
$rights = $line.split("%")[2]
$inheritance = $line.split("%")[3]
$propagation = $line.split("%")[4]
$audit = $line.split("%")[5]
} 

elseif ($line.StartsWith("HKU:\<SID>")) 
{
$fragment_path = $line.Substring(10)
foreach ($sid in $usersids) {
$sid_value = $sid.tostring().substring(11)
$current_path = "HKU:\$sid_value$fragment_path"
$error.clear()
try {
remove_object_audit -object_path $current_path -accounts $account_list -auditrights $rights -inheritanceflags $inheritance -propagationflags $propagation -auditflags $audit -type $audit_type
} catch {
"Error removing auditing on $current_path"
 }
if (!$error) {
Write-Host "Successfully removed auditing for $current_path"
}
}
}
else {
$current_path = $line
$error.clear()
try {
remove_object_audit -object_path $current_path -accounts $account_list -auditrights $rights -inheritanceflags $inheritance -propagationflags $propagation -auditflags $audit -type $audit_type
} catch {
"Error removing auditing on $current_path"
 }
if (!$error) {
Write-Host "Successfully removed auditing for $current_path"
}
}
}
}

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