# LOGDKFA

## Purpose

Configuring logging often requires a delicate balance.  Setting the logs to be too verbose can quickly overload system resources.  Insufficient logging can cause important events to be missed.  **LOGDKFA** allows you to throttle up logging and audit settings when needed in a granular fashion.  For example, you could configure more verbose logging based on event triggers such as:
* File downloads
* Administrative credentials invoked
* Alert triggered by SIEM or network sensor
* New programs installed
* Program execution (e.g. Powershell, cmd.exe)

Note that if you want to set filesystem and/or registry auditing, you need to globally enable object access auditing, a la:

@("Object Access","*","enable","enable")

**LOGDKFA** is designed to enable auditing for a period of time that you specify and then clean up after itself.  Note that the process does not survive being killed or a system reboot, so if it is interrupted before cleanup happens then you will have to restore the original settings manually.  It is recommended that you build configuration files that are tailored to your triggers.  

The default logging, file auditing, and registry auditing settings that are in the configuration files are based on the cheat sheets published by [Malware Archaelology](https://www.malwarearchaeology.com/cheat-sheets) .  Typically these configurations are appropriate for "steady state" operations and are best managed by group policy settings in large organizations.  **LOGDKFA** may be more useful when there is a requirement for very verbose logs (e.g. Windows Filtering Platform) for a short period of time.

## Configuration

Configuration steps are pretty simple:
* Configure the **audit_settings** array to configure the audit policy settings you want
* Edit **conf.json** to specify whether you want to enable filesystem auditing, registry auditing and the path for those configuration files.
* If needed, create your file auditing and registry auditing configurations as per the file_audit.conf and reg_audit.conf templates.   
* Ensure that the configuration files are placed in the same directory as the script (or the path(s) are passed to the script appropriately)

## Execution

Execute powershell logdkfa.ps1 <time in seconds> as an administrator.

Note that the default time is set to 300 seconds (5 minutes). Also, if you have multiple configuration files (beyond the default **conf.json**) be sure to pass the correct configuration file path as a parameter. 

## Contributions and Future

This script was designed for functionality.  It can be made much prettier with the help of smarter people putting eyes on it.  Contributions are very welcome!

Future plans include:
* Support for powershell logging and script block auditing
* Porting the audit_settings array to a conf file to facilitate flexibility
* Support for enabling special log types (outside of standard Security logs)
* Better error handling and settings validation
* A comparable capability for *nix systems 