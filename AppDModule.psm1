function Get-AppDApplications
<#
.Synopsis
   Get Apps in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplications
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(

    [Parameter()]
    [pscredential]$credential = (Get-Credential)

)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    $url = "$baseURL/$api/`?&output=JSON"
    $query = Invoke-RestMethod $URL -Headers $headers
    $query
}
END {
}
}

function Get-AppDAccount
<#
.Synopsis
   Get Accounts in AppD
.DESCRIPTION
   Retrieve AppDynamics Accounts
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(

    [Parameter()]
    [pscredential]$credential = (Get-Credential)

)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/api"
$api = 'accounts'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    $url = "$baseURL/$api/myaccount`?&output=JSON"
    $query = Invoke-RestMethod $URL -Headers $headers
    $query
}
END {
}
}


function Get-AppDEvents
<#
.Synopsis
   Get Application Events in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplication's events for a given timeframe
.EXAMPLE
   Get-AppDEvents -Application '9624', 'Prod_xperCRM' -EventType APPLICATION_ERROR, DIAGNOSTIC_SESSION, APPLICATION_CONFIG_CHANGE -Minutes 90 -Severity ERROR, WARN -credential $credential
.EXAMPLE
    Get-AppDEvents -Application 'Prod_xperCRM' -EventType SLOW -Minutes 90 -credential $credential
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application Name or ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [string[]]$Application = 'UAT-xperCRM',

    [Parameter()]
    [pscredential]$credential = (Get-Credential),

    [Parameter()]
    [ValidateSet(
        'ACTIVITY_TRACE','ADJUDICATION_CANCELLED','AGENT_ADD_BLACKLIST_REG_LIMIT_REACHED','AGENT_ASYNC_ADD_REG_LIMIT_REACHED','AGENT_CONFIGURATION_ERROR',
        'AGENT_DIAGNOSTICS','AGENT_ERROR_ADD_REG_LIMIT_REACHED','AGENT_EVENT','AGENT_METRIC_BLACKLIST_REG_LIMIT_REACHED','AGENT_METRIC_REG_LIMIT_REACHED',
        'AGENT_STATUS','ALREADY_ADJUDICATED','APPLICATION_CONFIG_CHANGE','APPLICATION_DEPLOYMENT','APPLICATION_ERROR',
        'APP_SERVER_RESTART','AZURE_AUTO_SCALING','BACKEND_DISCOVERED','BT_DISCOVERED','CONTROLLER_AGENT_VERSION_INCOMPATIBILITY',
        'CONTROLLER_ASYNC_ADD_REG_LIMIT_REACHED','CONTROLLER_ERROR_ADD_REG_LIMIT_REACHED','CONTROLLER_EVENT_UPLOAD_LIMIT_REACHED','CONTROLLER_METRIC_REG_LIMIT_REACHED','CONTROLLER_RSD_UPLOAD_LIMIT_REACHED',
        'CONTROLLER_STACKTRACE_ADD_REG_LIMIT_REACHED','CUSTOM','CUSTOM_ACTION_END','CUSTOM_ACTION_FAILED','CUSTOM_ACTION_STARTED',
        'DEADLOCK','DIAGNOSTIC_SESSION','DISK_SPACE','EMAIL_SENT','EUM_CLOUD_BROWSER_EVENT',
        'INFO_INSTRUMENTATION_VISIBILITY','INTERNAL_UI_EVENT','LICENSE','MACHINE_DISCOVERED','MEMORY',
        'MEMORY_LEAK_DIAGNOSTICS','MOBILE_CRASH_IOS_EVENT','MOBILE_CRASH_ANDROID_EVENT','NODE_DISCOVERED','NORMAL',
        'OBJECT_CONTENT_SUMMARY','POLICY_CANCELED_CRITICAL','POLICY_CANCELED_WARNING','POLICY_CLOSE_CRITICAL','POLICY_CLOSE_WARNING',
        'POLICY_CONTINUES_CRITICAL','POLICY_CONTINUES_WARNING','POLICY_DOWNGRADED','POLICY_OPEN_CRITICAL','POLICY_OPEN_WARNING',
        'POLICY_UPGRADED','RESOURCE_POOL_LIMIT','RUNBOOK_DIAGNOSTIC SESSION_END','RUNBOOK_DIAGNOSTIC SESSION_FAILED',
        'RUNBOOK_DIAGNOSTIC SESSION_STARTED','RUN_LOCAL_SCRIPT_ACTION_END','RUN_LOCAL_SCRIPT_ACTION_FAILED','RUN_LOCAL_SCRIPT_ACTION_STARTED',
        'SERVICE_ENDPOINT_DISCOVERED','SLOW','SMS_SENT','STALL','SYSTEM_LOG',
        'THREAD_DUMP_ACTION_END','THREAD_DUMP_ACTION_FAILED','THREAD_DUMP_ACTION_STARTED','TIER_DISCOVERED','VERY_SLOW',
        'WORKFLOW_ACTION_END','WORKFLOW_ACTION_FAILED','WORKFLOW_ACTION_STARTED',
    ignorecase=$False)]
    [string[]]
    $EventType = 'APPLICATION_ERROR, DIAGNOSTIC_SESSION',

    # Number of minutes back
    [int]$Minutes = 60,

    [ValidateSet('INFO', 'WARN', 'ERROR', ignorecase=$False)]
    [string[]]
    $Severity = 'INFO,WARN,ERROR'
)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$resource = 'events'
$eT = $EventType -join ','
$sev = $Severity -join ','
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($app in $Application) {
        $url = "$baseURL/$api/$app/$resource`?time-range-type=BEFORE_NOW&duration-in-mins=$Minutes&event-types=%20$eT&severities=$sev&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        foreach ($event in $query) {
            $event.eventTime = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddMilliSeconds($($Event.eventTime)))
        }
        $query
    }
}
END {
}
}


function Get-BusinessTransations
<#
.Synopsis
   Get BTs in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplication's monitored Business Transactions
.EXAMPLE
    Get-BusinessTransations -Application Prod_xperCRM -credential $credential
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application Name or ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [string[]]$Application = 'UAT-xperCRM',

    [Parameter()]
    [pscredential]$credential = (Get-Credential)


)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$resource = 'business-transactions'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($app in $Application) {
        $url = "$baseURL/$api/$app/$resource`?&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        $query
    }
}
END {
}
}

function Get-AppDTiers
<#
.Synopsis
   Get Tiers in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplication's Tiers
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application Name or ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [string[]]$Application = 'UAT-xperCRM',

    [Parameter()]
    [pscredential]$credential = (Get-Credential)


)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$resource = 'tiers'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($app in $Application) {
        $url = "$baseURL/$api/$app/$resource`?&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        $query
    }
}
END {
}
}


function Get-AppDBackends
<#
.Synopsis
   Get Backends in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplication's Backends
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application Name or ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [string[]]$Application = 'UAT-xperCRM',

    [Parameter()]
    [pscredential]$credential = (Get-Credential)


)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$resource = 'backends'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($app in $Application) {
        $url = "$baseURL/$api/$app/$resource`?&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        $query
    }
}
END {
}
}

function Get-AppDNodes
<#
.Synopsis
   Get Nodes in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplication's Nodes
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application Name or ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [string[]]$Application = 'UAT-xperCRM',

    [Parameter()]
    [pscredential]$credential = (Get-Credential)


)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$resource = 'nodes'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($app in $Application) {
        $url = "$baseURL/$api/$app/$resource`?&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        $query
    }
}
END {
}
}


function Get-AppDMetrics
<#
.Synopsis
   Get Metrics in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplication's Metrics
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application Name or ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [string[]]$Application = 'UAT-xperCRM',

    [Parameter()]
    [pscredential]$credential = (Get-Credential)


)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$resource = 'metrics'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($app in $Application) {
        $url = "$baseURL/$api/$app/$resource`?&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        $query
    }
}
END {
}
}

function Get-AppDMetricData
<#
.Synopsis
   Get MetricData in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplication's MetricData
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application Name or ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [string[]]$Application = 'UAT-xperCRM',

    [Parameter()]
    [pscredential]$credential = (Get-Credential),

    [Parameter()]
    [string[]]$metric,

    # Number of minutes back
    [int]$Minutes = 60

)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$resource = 'metric-data'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($app in $Application) {
        $url = "$baseURL/$api/$app/$resource`?metric-path=$metric&time-range-type=BEFORE_NOW&duration-in-mins=$minutes&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        $query
    }
}
END {
}
}

function Get-HealthRuleViolations
<#
.Synopsis
   Get Application HealthRule Violations in AppD
.DESCRIPTION
   Retrieve AppDynamics Aplication's HealthRule Violations for a given timeframe
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application Name or ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [string[]]$Application = 'UAT-xperCRM',

    [Parameter()]
    [pscredential]$credential = (Get-Credential),


    # Number of minutes back
    [int]$Minutes = 60

)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/rest"
$api = 'applications'
$resource = 'problems/healthrule-violations'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}

}
PROCESS {
    Foreach ($app in $Application) {
        $url = "$baseURL/$api/$app/$resource`?time-range-type=BEFORE_NOW&duration-in-mins=$Minutes&event-types=%20$eT&severities=$sev&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        $query | Add-Member -NotePropertyName startTime -NotePropertyValue ''
        $query | Add-Member -NotePropertyName endTime -NotePropertyValue ''

        foreach ($event in $query) {
            
            $event.startTime = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddMilliSeconds($($Event.startTimeInMillis)))
            $event.endTime = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddMilliSeconds($($Event.endTimeInMillis)))

        }
        $query
    }
}
END {
}
}

function Get-ActionSuppressions
<#
.Synopsis
   Get Action Suppressions in AppD
.DESCRIPTION
   Retrieve AppDynamics Application Suppressions
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application ID
    [Parameter(
    Mandatory=$true,
    ValueFromPipelineByPropertyName=$true,
    ValueFromPipeline=$true,
    Position=0)]
    [int32[]]$ApplicationId,

    [Parameter()]
    [pscredential]$credential = (Get-Credential)


)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$account = Get-AppDAccount -credential $credential | Select -expand id
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/api/accounts/$account"
$api = 'applications'
$resource = 'actionsuppressions'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($app in $ApplicationId) {
        $url = "$baseURL/$api/$app/$resource`?&output=JSON"
        $query = Invoke-RestMethod $URL -Headers $headers
        $query.actionSuppressions
    }
}
END {
}
}

function Remove-ActionSuppression
<#
.Synopsis
   Get Action Suppressions in AppD
.DESCRIPTION
   Retrieve AppDynamics Application Suppressions
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application ID
    [Parameter(
    Mandatory=$true,
    Position=0)]
    [int32]$ApplicationId,

    [Parameter(
    Mandatory=$true,
    Position=1)]
    [int32[]]$ActionSuppressionId,

    [Parameter()]
    [pscredential]$credential = (Get-Credential)

)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$account = Get-AppDAccount -credential $credential | Select -expand id
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/api/accounts/$account"
$api = 'applications'
$resource = 'actionsuppressions'
$headers = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))}


}
PROCESS {
    Foreach ($action in $ActionSuppressionId) {
        $url = "$baseURL/$api/$applicationId/$resource/$Action"
        Invoke-RestMethod $URL -Headers $headers -Method Delete
    }
}
END {
}
}

function New-ActionSuppression
<#
.Synopsis
   Create Action Suppressions in AppD
.DESCRIPTION
   Create AppDynamics Application Suppressions
.EXAMPLE
.EXAMPLE
#>
{
[CmdletBinding()]
[Alias()]
[OutputType([int])]
Param
(
    # AppD Application ID
    [Parameter(
    Mandatory=$true,
    Position=0)]
    [int32[]]$ApplicationId,

    [Parameter()]
    [pscredential]$credential = (Get-Credential),

    [string]$name = 'Action suppression created by PowerShell AppDModule',

    [datetime]$startTime = (Get-Date),

    [datetime]$endTime = (Get-Date).AddHours(2)


)

BEGIN {
$AppDAccount = "$($MyInvocation.MyCommand.Module.PrivateData.AppDAccount)"
$account = Get-AppDAccount -credential $credential | Select -expand id
$baseURL = "https://$AppDAccount.saas.appdynamics.com/controller/api/accounts/$account"
$api = 'applications'
$resource = 'actionsuppressions'
$startTimeMillis = $starttime | Get-date -Format "yyyy-MM-dd'T'hh:mm:ssK"
Write-Verbose $startTimeMillis
[System.DateTimeOffset]$endTimeMillis = $endTime | Get-date -Format "yyyy-MM-dd'T'hh:mm:ss+0000"
Write-Verbose $endTimeMillis
$timerange = @{startTimeMillis = $startTimeMillis; endTimeMillis = $endTimeMillis}
Write-Verbose $timerange
$headers = @{
    "Authorization" = 'Basic '+ [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("$($credential.UserName):$($credential.GetNetworkCredential().password)"))
    "Content-Type" = "application/vnd.appd.cntrl+json;v=1"
}


}
PROCESS {
    Foreach ($appid in $ApplicationId) {
        $url = "$baseURL/$api/$appId/$resource"
        Write-Verbose $url
        $body = @{
        name = $name;
        timeRange = $timerange;
        affects = @{type = 'APP'}
        }
        $payload = $body | ConvertTo-Json
        
        Invoke-RestMethod $URL -Headers $headers -Method POST -Body $payload
    }
}
END {
}
}

<# Examples
#Get-AppDApplications -credential $credential | select -ExpandProperty name | Get-HealthRuleViolations -credential $credential | select -ExpandProperty affectedEntityDefinition
Get-AppDApplications -credential $credential | where name -eq 'UAT-xperCRM' | select -ExpandProperty id | Get-ActionSuppressions -credential $credential
#>