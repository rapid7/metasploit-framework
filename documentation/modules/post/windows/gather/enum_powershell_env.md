## Vulnerable Application

This module will enumerate Microsoft PowerShell settings.


## Verification Steps

1. Start msfconsole
1. Get a session
1. Do: `use post/windows/gather/enum_powershell_env`
1. Do: `set SESSION <session id>`
1. Do: `run`

## Options

## Scenarios

### Windows 7 (6.1 Build 7601, Service Pack 1)

```
msf6 > use post/windows/gather/enum_powershell_env
msf6 post(windows/gather/enum_powershell_env) > set session 1
session => 1
msf6 post(windows/gather/enum_powershell_env) > run

[*] Running module against test (192.168.200.158)
[*] PowerShell is installed on this system.
[*] Version: 2.0
[*] Execution Policy: RemoteSigned
[*] Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[*] No PowerShell Snap-Ins are installed
[*] PowerShell Modules paths:
[*] 	C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
[*] 	C:\Program Files (x86)\Microsoft SQL Server\120\Tools\PowerShell\Modules\
[*] 	C:\Program Files (x86)\AutoIt3\AutoItX
[*] PowerShell Modules:
[*] 	PSDiagnostics
[*] 	TroubleshootingPack
[*] 	SQLASCMDLETS
[*] 	SQLPS
[*] 	AutoItX.chm
[*] 	AutoItX.psd1
[*] 	AutoItX3.Assembly.dll
[*] 	AutoItX3.Assembly.xml
[*] 	AutoItX3.dll
[*] 	AutoItX3.PowerShell.dll
[*] 	AutoItX3_DLL.h
[*] 	AutoItX3_DLL.lib
[*] 	AutoItX3_x64.dll
[*] 	AutoItX3_x64_DLL.lib
[*] 	Examples
[*] Checking if users have PowerShell profiles
[*] Running with elevated privileges. Extracting user list ...
[*] Checking asdf
[*] Checking DefaultAppPool
[*] Checking MSSQL$SQLEXPRESS
[*] Checking MSSQLSERVER
[*] Checking postgres
[*] Checking test
[*] Checking user
[*] Found PowerShell profile 'C:\Users\user\Documents\WindowsPowerShell\profile.ps1' for user:
Get-Host | Select-Object Version

[*] Post module execution completed
```

### Windows 11 Pro (10.0.22000 N/A Build 22000)

```

msf6 > use post/windows/gather/enum_powershell_env
msf6 post(windows/gather/enum_powershell_env) > set session 1
session => 1
msf6 post(windows/gather/enum_powershell_env) > run

[*] Running module against WinDev2110Eval (192.168.200.140)
[*] PowerShell is installed on this system.
[*] Version: 2.0
[*] Execution Policy: AllSigned
[*] Path: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[*] PowerShell Snap-Ins:
[*] 	Snap-In: WDeploySnapin3.0
[*] 		(Default): 
[*] 		ApplicationBase: C:\Program
[*] 		AssemblyName: Microsoft.Web.Deployment.PowerShell,
[*] 		Description: This
[*] 		ModuleName: Microsoft.Web.Deployment.PowerShell.dll
[*] 		PowerShellVersion: 2.0
[*] 		Vendor: Microsoft
[*] 		Version: 9.0.0.0
[*] PowerShell Modules paths:
[*] 	C:\Users\User\Documents\WindowsPowerShell\Modules
[*] 	C:\Program Files\WindowsPowerShell\Modules
[*] 	C:\Windows\system32\WindowsPowerShell\v1.0\Modules
[*] PowerShell Modules:
[*] 	Azure
[*] 	Azure.AnalysisServices
[*] 	Azure.Storage
[*] 	AzureRM
[*] 	AzureRM.AnalysisServices
[*] 	AzureRM.ApiManagement
[*] 	AzureRM.ApplicationInsights
[*] 	AzureRM.Automation
[*] 	AzureRM.Backup
[*] 	AzureRM.Batch
[*] 	AzureRM.Billing
[*] 	AzureRM.Cdn
[*] 	AzureRM.CognitiveServices
[*] 	AzureRM.Compute
[*] 	AzureRM.Consumption
[*] 	AzureRM.ContainerInstance
[*] 	AzureRM.ContainerRegistry
[*] 	AzureRM.DataFactories
[*] 	AzureRM.DataFactoryV2
[*] 	AzureRM.DataLakeAnalytics
[*] 	AzureRM.DataLakeStore
[*] 	AzureRM.DevTestLabs
[*] 	AzureRM.Dns
[*] 	AzureRM.EventGrid
[*] 	AzureRM.EventHub
[*] 	AzureRM.HDInsight
[*] 	AzureRM.Insights
[*] 	AzureRM.IotHub
[*] 	AzureRM.KeyVault
[*] 	AzureRM.LogicApp
[*] 	AzureRM.MachineLearning
[*] 	AzureRM.MachineLearningCompute
[*] 	AzureRM.MarketplaceOrdering
[*] 	AzureRM.Media
[*] 	AzureRM.Network
[*] 	AzureRM.NotificationHubs
[*] 	AzureRM.OperationalInsights
[*] 	AzureRM.PowerBIEmbedded
[*] 	AzureRM.Profile
[*] 	AzureRM.RecoveryServices
[*] 	AzureRM.RecoveryServices.Backup
[*] 	AzureRM.RecoveryServices.SiteRecovery
[*] 	AzureRM.RedisCache
[*] 	AzureRM.Relay
[*] 	AzureRM.Resources
[*] 	AzureRM.Scheduler
[*] 	AzureRM.ServerManagement
[*] 	AzureRM.ServiceBus
[*] 	AzureRM.ServiceFabric
[*] 	AzureRM.SiteRecovery
[*] 	AzureRM.Sql
[*] 	AzureRM.Storage
[*] 	AzureRM.StreamAnalytics
[*] 	AzureRM.Tags
[*] 	AzureRM.TrafficManager
[*] 	AzureRM.UsageAggregates
[*] 	AzureRM.Websites
[*] 	Microsoft.PowerShell.Operation.Validation
[*] 	PackageManagement
[*] 	Pester
[*] 	PowerShellGet
[*] 	PSReadline
[*] 	AppBackgroundTask
[*] 	AppLocker
[*] 	AppvClient
[*] 	Appx
[*] 	AssignedAccess
[*] 	BitLocker
[*] 	BitsTransfer
[*] 	BranchCache
[*] 	CimCmdlets
[*] 	ConfigCI
[*] 	ConfigDefender
[*] 	ConfigDefenderPerformance
[*] 	Defender
[*] 	DeliveryOptimization
[*] 	DirectAccessClientComponents
[*] 	Dism
[*] 	DnsClient
[*] 	EventTracingManagement
[*] 	Get-NetView
[*] 	HostNetworkingService
[*] 	International
[*] 	iSCSI
[*] 	ISE
[*] 	Kds
[*] 	Microsoft.PowerShell.Archive
[*] 	Microsoft.PowerShell.Diagnostics
[*] 	Microsoft.PowerShell.Host
[*] 	Microsoft.PowerShell.LocalAccounts
[*] 	Microsoft.PowerShell.Management
[*] 	Microsoft.PowerShell.ODataUtils
[*] 	Microsoft.PowerShell.Security
[*] 	Microsoft.PowerShell.Utility
[*] 	Microsoft.Windows.Bcd.Cmdlets
[*] 	Microsoft.WSMan.Management
[*] 	MMAgent
[*] 	MsDtc
[*] 	NetAdapter
[*] 	NetConnection
[*] 	NetEventPacketCapture
[*] 	NetLbfo
[*] 	NetNat
[*] 	NetQos
[*] 	NetSecurity
[*] 	NetSwitchTeam
[*] 	NetTCPIP
[*] 	NetworkConnectivityStatus
[*] 	NetworkSwitchManager
[*] 	NetworkTransition
[*] 	PcsvDevice
[*] 	PersistentMemory
[*] 	PKI
[*] 	PnpDevice
[*] 	PrintManagement
[*] 	ProcessMitigations
[*] 	Provisioning
[*] 	PSDesiredStateConfiguration
[*] 	PSDiagnostics
[*] 	PSScheduledJob
[*] 	PSWorkflow
[*] 	PSWorkflowUtility
[*] 	ScheduledTasks
[*] 	SecureBoot
[*] 	SmbShare
[*] 	SmbWitness
[*] 	StartLayout
[*] 	Storage
[*] 	StorageBusCache
[*] 	TLS
[*] 	TroubleshootingPack
[*] 	TrustedPlatformModule
[*] 	UEV
[*] 	VMDirectStorage
[*] 	VpnClient
[*] 	Wdac
[*] 	Whea
[*] 	WindowsDeveloperLicense
[*] 	WindowsErrorReporting
[*] 	WindowsSearch
[*] 	WindowsUpdate
[*] Checking if users have PowerShell profiles
[*] Checking User
[*] Post module execution completed
```

