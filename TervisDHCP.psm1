#Requires -Modules WriteVerboseAdvanced, TervisEnvironment
#Requires -Version 5

function Get-TervisDhcpServerv4Scope {
    param(
        [Parameter(Mandatory, ParameterSetName="ScopeID")]$ScopeID,

        [Parameter(Mandatory, ParameterSetName="Environment")]
        [ValidateScript({$_ -in $(Get-TervisEnvironmentName) })]
        $Environment
    )
    process {
        Get-DhcpServerv4Scope -ComputerName $(
            Get-DhcpServerInDC | 
            select -First 1 -ExpandProperty DNSName
        ) |
        where {-not $ScopeID -or $_.ScopeID -EQ $ScopeID} |
        Add-DhcpServerv4ScopeProperties -PassThru |
        where {-not $Environment -or $_.Environment -eq $Environment}
    }   
}

function Add-DhcpServerv4ScopeProperties {
    param (
        [Parameter(ValueFromPipeline)]$DhcpServerv4Scope,
        [Switch]$PassThru
    )
    process {
        $DhcpServerv4Scope | 
        Add-Member -MemberType ScriptProperty -Name VLan -Value {
            $This.Name -match 'VLAN (?<VLANId>..)' | Out-Null
            $Local:Matches.VLANId -as [int] 
        } -PassThru:$PassThru | 
        Add-Member -MemberType ScriptProperty -Name Environment -Value { 
            $This.Name -split " " | 
            select -First 1 |
            Where {$_ -in $(Get-TervisEnvironmentName)}
        } -PassThru:$PassThru
    }
}

function Set-TervisDHCPForVM {
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [Parameter(Mandatory)]$DHCPScope,
        [switch]$PassThru
    )
    $VMNetworkAdapter = $VM | Get-TervisVMNetworkAdapter 
    $DHCPServerName = Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName
    $FreeIPAddress = $DHCPScope | Get-DhcpServerv4FreeIPAddress -ComputerName $DHCPServerName
    $DHCPScope | Add-DhcpServerv4Reservation -ClientId $VMNetworkAdapter.MacAddressWithDashes -ComputerName $DHCPServerName -IPAddress $FreeIPAddress -Name $VM.Name -Description $VM.Name

    if($PassThru) {$VM}
}

function Remove-TervisDHCPForVM {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [switch]$PassThru
    )
    $VMNetworkAdapter = $VM | Get-TervisVMNetworkAdapter
    $DHCPServerName = Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName

    Get-DhcpServerv4Scope -ComputerName $DHCPServerName | 
    Get-DhcpServerv4Lease -ComputerName $DHCPServerName | 
    where ClientID -EQ $VMNetworkAdapter.MacAddressWithDashes |
    Write-VerboseAdvanced -PassThrough -Verbose:($VerbosePreference -ne "SilentlyContinue") |
    Remove-DhcpServerv4Reservation -ComputerName $DHCPServerName -PassThru -Confirm |
    Remove-DhcpServerv4Lease -ComputerName $DHCPServerName  -Confirm

    if($PassThru) {$VM}
}

function Remove-TervisDHCPReservationAndLease {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipeline)]$MacAddressWithDashes
    )
    process {
        $DHCPServerName = Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName

        Get-DhcpServerv4Scope -ComputerName $DHCPServerName | 
        Get-DhcpServerv4Lease -ComputerName $DHCPServerName | 
        where ClientID -EQ $MacAddressWithDashes |
        Write-VerboseAdvanced -PassThrough -Verbose:($VerbosePreference -ne "SilentlyContinue") |
        Remove-DhcpServerv4Reservation -ComputerName $DHCPServerName -PassThru -Confirm |
        Remove-DhcpServerv4Lease -ComputerName $DHCPServerName  -Confirm
    }
}

function Find-DHCPServerv4Lease {
    [CmdletBinding()]
    param(
        [parameter(Mandatory, ValueFromPipelineByPropertyName)]$MACAddressWithDashes
    )
    $DHCPServerName = Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName

    Get-DhcpServerv4Scope -ComputerName $DHCPServerName | 
    Get-DhcpServerv4Lease -ComputerName $DHCPServerName | 
    where ClientID -EQ $MACAddressWithDashes
}

function Find-DHCPServerv4LeaseIPAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName="MACAddressWithDashes")]
        $MACAddressWithDashes,
        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName="HostName")]
        $HostName,
        [Switch]$AsString
    )
    $DHCPServerName = Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName

    $IPAddress = Get-DhcpServerv4Scope -ComputerName $DHCPServerName | 
    Get-DhcpServerv4Lease -ComputerName $DHCPServerName | 
    where {-not $MACAddressWithDashes -or  $_.ClientID -EQ $MACAddressWithDashes} |
    where {-not $HostName -or  $_.HostName -match $HostName} |
    Select -ExpandProperty IPAddress

    if ($AsString) {
        if ($IPAddress -is [String]) {
            $IPAddress
        } else {
            $IPAddress.IPAddressToString
        }
    } else {
        $IPAddress
    }
}

function Invoke-TervisDHCPv4EdgeRouterChanges {
    param (
        [Parameter(Mandatory)]$Hostname,
        [Parameter(Mandatory,ParameterSetName="ScopeID")]$ScopeID,
        [Parameter(Mandatory,ParameterSetName="Environment")]$Environment
    )
    if (-Not $ScopeID) {
        $ScopeID = Get-TervisDhcpServerv4Scope -Environment $Environment | 
        Select-Object -ExpandProperty ScopeID
    }
    $DHCPServerName = Get-DhcpServerInDC |  select -ExpandProperty DNSName -First 1
    
    $MACAddressesToMoveToNewGateway = Get-DhcpServerv4Lease -ScopeId $Scope.ScopeId -ComputerName $DHCPServerName | 
    Where-Object Hostname -Match $Hostname |
    Select-Object -ExpandProperty ClientID
    
    $MACAddressParameter = (@("eq") +$MACAddressesToMoveToNewGateway)

    Add-DhcpServerv4Policy -Name "Default gateway edgerouter in Infrastructure" -Condition OR -ComputerName $DHCPServerName -ScopeId $Scope.ScopeID -MacAddress $MACAddressParameter
    Set-DhcpServerv4OptionValue -ComputerName $DHCPServerName -PolicyName "Default gateway edgerouter in Infrastructure" -ScopeId $Scope.ScopeID -Router 10.172.48.150
    
    Get-DhcpServerv4Reservation -ComputerName $DHCPServerName -ScopeId $Scope.ScopeId |
    Where-Object Name -Match INF-SCDPM |
    ForEach-Object {
        Set-DhcpServerv4OptionValue -ComputerName $DHCPServerName -Router 10.172.48.150 -ReservedIP $_.IPAddress
    }
}

function Set-TervisDHCPv4ReservationRouterToEdgeRouter {
    param (
        [Parameter(Mandatory)]$Hostname,
        [Parameter(Mandatory,ParameterSetName="ScopeID")]$ScopeID,
        [Parameter(Mandatory,ParameterSetName="Environment")]$Environment
    )
    if (-Not $ScopeID) {
        $ScopeID = Get-TervisDhcpServerv4Scope -Environment $Environment | 
        Select-Object -ExpandProperty ScopeID
    }
    $DHCPServerName = Get-DhcpServerInDC |  select -ExpandProperty DNSName -First 1
    
    Get-DhcpServerv4Reservation -ComputerName $DHCPServerName -ScopeId $ScopeID |
    Where-Object Name -Match $Hostname |
    ForEach-Object {
        Set-DhcpServerv4OptionValue -ComputerName $DHCPServerName -Router 10.172.48.150 -ReservedIP $_.IPAddress
    }
}