function Get-TervisDhcpServerv4Scope {
    param(
        [Parameter(Mandatory)]$ScopeID
    )
    process {
        $DhcpServerv4Scope = Get-DhcpServerv4Scope -ScopeId $ScopeID -ComputerName $(Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName)
        $DhcpServerv4Scope | Mixin-DhcpServerv4Scope
        $DhcpServerv4Scope
    }   
}

filter Mixin-DhcpServerv4Scope {
    $_ | Add-Member -MemberType ScriptProperty -Name VLan -Value { $This.Name -match 'VLAN (?<VLANId>..)' | Out-Null; $Local:Matches.VLANId -as [int] }
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
    param(
        [parameter(Mandatory, ValueFromPipeline)]$VM,
        [switch]$PassThru
    )
    $VMNetworkAdapter = $VM | Get-TervisVMNetworkAdapter 
    $DHCPServerName = Get-DhcpServerInDC | select -First 1 -ExpandProperty DNSName

    Get-DhcpServerv4Scope -ComputerName $DHCPServerName | 
    Get-DhcpServerv4Lease -ComputerName $DHCPServerName | 
    where ClientID -EQ $VMNetworkAdapter.MacAddressWithDashes |
    Remove-DhcpServerv4Reservation -ComputerName $DHCPServerName -Confirm

    if($PassThru) {$VM}
}
