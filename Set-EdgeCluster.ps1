#requires -version 4
Param (

    [Parameter(Mandatory = $true, Position = 1)]
	[ValidateNotNullOrEmpty()]
	[string]$vcdServer,

	[Parameter(Mandatory = $true, Position = 2)]
	[ValidateNotNullOrEmpty()]
	[string]$providerVDC,

	[Parameter(Mandatory = $true, Position = 3)]
	[ValidateNotNullOrEmpty()]
	[string]$vcServer,

	[Parameter(Mandatory = $True, Position = 4)]
	[ValidateNotNullOrEmpty()]
	[string]$destinationParentCluster,
	
	[Parameter(Mandatory = $True, Position = 5)]
	[ValidateNotNullOrEmpty()]
	[string]$resourcePool

    )
# Script version
  $version = 0.9
# Name: Set-EdgeCluster.ps1
# Author: Giuliano Bertello <giuliano.bertello@gmail.com>
# Date: 08/01/2018
# Script Logic:
# - get pvdc name from vCD
# - create new rp under edge cluster matching pvdc name
# - from pvdca add new rp rp-edge-pvdca
# - get rp-edge-pvdca id
# - from vcd edit pvdc as system admin and metadata placement.resourcepool.edge = <res-id>

Function Write-Log {
	
	[CmdletBinding()]
	Param(
	[Parameter(Mandatory = $True, Position=1)]
	[ValidateNotNullOrEmpty()]
	[string]$logFile,
		
	[Parameter(Mandatory = $False, Position=2)]
	[int]$severity = 0,

	[Parameter(Mandatory = $False, Position=3)]
	[string]$type = "terse",
	   
	[Parameter(Mandatory = $True, Position=4)]
	[ValidateNotNullOrEmpty()]
	[string]$logMessage
	) 

	$timestamp = (Get-Date -Format ("[dd-MM-yyyy HH:mm:ss] "))
	$ui = (Get-Host).UI.RawUI

	switch ($severity) {

			{$_ -eq 1} {$ui.ForegroundColor = "red"; $type ="full"; $LogEntry = $timestamp + ":Error: " + $logMessage; break;}
			{$_ -eq 0} {$ui.ForegroundColor = "green"; $LogEntry = $timestamp + ":Info: " + $logMessage; break;}
			{$_ -eq 2} {$ui.ForegroundColor = "yellow"; $LogEntry = $timestamp + ":Warning: " + $logMessage; break;}
			{$_ -eq 3} {$ui.ForegroundColor = "cyan"; $LogEntry = $timestamp + ":Info: " + $logMessage; break;}
			{$_ -eq 4} {$ui.ForegroundColor = "gray"; $LogEntry = $timestamp + ":Global: " + $logMessage; break;}

	}
	switch ($type) {
	   		"console"	{
				Write-Output $LogEntry
				break
			}
			"full"	{
				Write-Host $LogEntry
				$LogEntry | Out-file $logFile -Append;
				break;
			}
			"logonly"	{
				$LogEntry | Out-file $logFile -Append
				break
			}
		 
	}

	$ui.ForegroundColor = "white" 

} 
Function Get-Error {
	[CmdletBinding()]
	Param(
	[Parameter(Mandatory = $True, Position = 1)]
	[ValidateNotNullOrEmpty()]
	[string]$errorMessage
	)   
	Write-Log $logFile 1 "full" "There has been an error, the error message is: **** $errorMessage ****"
}

Clear-Host

# Global environment variables
# vCD API version
$apiVer = "29.0"
# Create a timestamp for the log file 
$logfileTimeStamp = (Get-Date -Format ("dd-MM-yyyy-HH-mm-ss"))
# Script log file name
$logFile = $logfileTimeStamp + "-Set-EdgeCluster.ps1.log"
# Script title
$scriptHeader = "Set Edge cluster on vCloud Director - Version: $version"

Write-Log $logFile 0 "full" "*************************** SCRIPT STARTED ***************************"
Write-Log $logFile 0 "full" $scriptHeader

#region Bypass untrusted certificates
# --- Work with Untrusted Certificates
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
        Add-Type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;
        public class TrustAllCertsPolicy : ICertificatePolicy {
            public bool CheckValidationResult(
                ServicePoint srvPoint, X509Certificate certificate,
                WebRequest request, int certificateProblem) {
                return true;
            }
        }
"@
	[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
	Write-Log $logFile 0 "full" "Added TrustAllCertsPolicy policy"
    }
	else {
		Write-Log $logFile 0 "full" "TrustAllCertsPolicy policy already installed."
    }
	# adding all security protocols
	$SecurityProtocols = @(
		[System.Net.SecurityProtocolType]::Ssl3,
		[System.Net.SecurityProtocolType]::Tls,
		[System.Net.SecurityProtocolType]::Tls12
    )
	[System.Net.ServicePointManager]::SecurityProtocol = $SecurityProtocols -join ","
	Write-Log $logFile 0 "full" "Adding security protocol Tls,Tls12,Ssl3"

#endregion Bypass untrusted certificates
Write-Log $logFile 0 "full" "Log file name is: $logFile"

# Get credentials section
Write-Log $logFile 0 "full" "*********************************************************************"
Write-Log $logFile 0 "full" "Provide the vCloud Director system admin credential:"
Try {
	$vcdCredential = Get-Credential $null
	Write-Log $logFile 0 "full" "vCloud Director credential accepted."
}
Catch {
	Get-Error $_.Exception.Message
	Write-Log $logFile 1 "full" "vCloud Director redentials empty or uncomplete! Exiting"
	break
}
Write-Log $logFile 0 "full" "Provide vCenter Server system admin credential:"
Try {
	$vcCredential = Get-Credential $null
	Write-Log $logFile 0 "full" "vCenter Server credential accepted."
}
Catch {
	Get-Error $_.Exception.Message
	Write-Log $logFile 1 "full" "vCenter Server credentials empty or uncomplete! Exiting"
	break
}
Write-Log $logFile 0 "full" "*********************************************************************"

## Configure vCD authentication and prepare rest call
# Username and password
$username =  $vcdCredential.Username + "@system"
$password = ($vcdCredential.GetNetworkCredential()).Password

# Build authorization 
$auth = $username + ':' + $password

# Encode basic authorization for the header
$Encoded = [System.Text.Encoding]::UTF8.GetBytes($auth)
$EncodedPassword = [System.Convert]::ToBase64String($Encoded)
 
# Define vCD header
$headers = @{
	"Accept"="application/*+xml;version=$apiVer"
	"Authorization"="Basic $EncodedPassword"
}
	# Get a vCD token. The token is stored inside $vcdSession var which is later passed as -WebSession
	Try {
		Write-Log $logFile 0 "full" "Connecting to vCloud Director Server $vcdServer"
		$URI = "https://$vcdServer/api/sessions"
		$response = Invoke-RestMethod -Method Post -URI $URI -Headers $Headers -Session vcdSession
		Write-Log $logFile 0 "full" "Connected to $vcdServer"
		Write-Log $logFile 0 "full" "*********************************************************************"
	}
	Catch {
		Get-Error $_.Exception.Message
		Write-Log $logFile 1 "full" "Error connecting to vCloud Director $vcdServer"
		break
	}
	
	# Connect to vCenter Server
	Try {
		Write-Log $logFile 0 "full" "Connecting to vCenter Server $vcServer"
		Connect-VIServer -Server $vcServer -Credential $vcCredential -WarningAction SilentlyContinue | Out-Null 
		Write-Log $logFile 0 "full" "Connected to $vcServer"
		Write-Log $logFile 0 "full" "*********************************************************************"
	}
	Catch {
		Get-Error $_.Exception.Message
		Write-Log $logFile 1 "full" "Error connecting to vCenter Server $vcServer"
		break
	}

	# Get PVDC list and validate input providerVDC
	$URI = "https://$vcdServer/api/query?type=providerVdc"
	$response = Invoke-RestMethod -Uri $URI -Headers $headers -Method GET -WebSession $vcdSession
	$pvdcList = $response.QueryResultRecords
	$pvdcFound = $false
	foreach ($pvdc in $pvdcList.VMWProviderVdcRecord) {
		if ($pvdc.name.ToLower() -eq $providerVDC.ToLower()) {
			$pvdcFound = $true
			$pvdcHref = $pvdc.href
			break
		}
	}
	
	# Validate parent cluster 
	$parentCluster = Get-Cluster -Name $destinationParentCluster
		
	# verify providerVDC and destinationParentCluster are valid
	if ($pvdcFound) { 
		
		Write-Log $logFile 0 "full" "Provider VDC $providerVDC validated"

		if ($parentCluster) {

			Write-Log $logFile 0 "full" "Cluster resource pool $destinationParentCluster validated"
			# Create edge resource pool
			Try {
				New-ResourcePool -Location $destinationParentCluster -Name $resourcePool | Out-Null
				Write-Log $logFile 0 "full" "Resource pool $resourcePool created successfully."
				$rpId = (Get-ResourcePool -Name $resourcePool | Get-View).MoRef.Value
			}
			Catch {
				Get-Error $_.Exception.Message
				Write-Log $logFile 1 "full" "Error creating resource pool $resourcePool"
				break
			}

			# Add PVDC metadata
			$headers = @{
				"Accept"="application/*+xml;version=$apiVer"
				"Authorization"="Basic $EncodedPassword"
				"Content-Type"="application/vnd.vmware.vcloud.metadata+xml"
			}
			$URI = $pvdcHref + "/metadata"
			Write-Host $URI 
			#$URI = "https://vcd.cloudlab.local/api/admin/providervdc/47e47865-d384-44af-82b6-47dbd5074abd/metadata"
			Write-Host $rpId
			$body = @"
			<?xml version="1.0" encoding="UTF-8"?>
			<Metadata xmlns="http://www.vmware.com/vcloud/v1.5" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" type="application/vnd.vmware.vcloud.metadata+xml">
				<MetadataEntry type="application/vnd.vmware.vcloud.metadata.value+xml">
					<Domain	visibility="READONLY">SYSTEM</Domain>
					<Key>placement.resourcepool.edge</Key>
					<TypedValue xsi:type="MetadataStringValue">
						<Value>$rpId</Value>
					</TypedValue>
				</MetadataEntry>
			</Metadata>cls
"@
			Try {
				$response = Invoke-RestMethod -Uri $URI -Headers $headers -Body $body -Method POST -WebSession $vcdSession
			}
			Catch {
				Get-Error $_.Exception.Message
				Write-Log $logFile 1 "full" "Error creating metadata"
				break
			}
		}
		else { 	Write-Log $logFile 0 "full" "Could not find cluster resource pool $destinationParentCluster" 	}
	}
	else { 	Write-Log $logFile 0 "full" "Could not find Provider VDC $providerVDC" 	}
	#>
	
	
	
	
	<#
	# Get Resource pool and validate destinationParentCluster 
	# can't do this from vCD because management-edge is not presented into vCD
	$URI = "https://$vcdServer/api/query?type=resourcePool&fields=name,vc"
	$response = Invoke-RestMethod -Uri $URI -Headers $headers -Method GET -WebSession $vcdSession
	$resourcePoolList = $response.QueryResultRecords.ResourcePoolRecord
	$rpFound = $false
	foreach ($rp in $resourcePoolList) {
		if ($rp.name.ToLower() -eq $destinationParentCluster.ToLower()) {
			$vcHref = $rp.vc
			$rpFound = $true
			break
		}
	}
	#>

