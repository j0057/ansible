
<#
Import-Module "C:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ResourceManager\AzureResourceManager\AzureResourceManager.psd1"
#>

$ErrorActionPreference = "stop"

function Ensure-ResourceGroup
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name,

        [Parameter(Mandatory)]
        [String] $Location
    )

    $ResourceGroup = Get-AzureResourceGroup -Name $Name -ErrorAction Ignore
    if ($ResourceGroup -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: resource group ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: new resource group"
        $ResourceGroup = New-AzureResourceGroup -Location $Location -Name $Name
    }

    $Context | Add-Member -NotePropertyName ResourceGroup -NotePropertyValue $ResourceGroup
    return $Context
}

function Ensure-StorageAccount
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name
    )

    $StorageAccount = $Context.ResourceGroup | Get-AzureStorageAccount -Name $Name -ErrorAction Ignore
    if ($StorageAccount -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: storage account ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: new storage account"
        $StorageAccount = $Context.ResourceGroup | New-AzureStorageAccount -Name $Name -Type Standard_GRS
    }

    $Context | Add-Member -NotePropertyName StorageAccount -NotePropertyValue $StorageAccount
    return $Context
}

function Ensure-PublicIP
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name
    )

    $PublicIP = $Context.ResourceGroup | Get-AzurePublicIpAddress -Name $Name -ErrorAction Ignore
    if ($PublicIP -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: public ip ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: new public ip"
        $PublicIP = $Context.ResourceGroup | New-AzurePublicIpAddress -Name $Name -AllocationMethod Dynamic
    }

    $Context | Add-Member -NotePropertyName PublicIP -NotePropertyValue $PublicIP
    return $Context
}

function Ensure-VirtualNetwork
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name,

        [String] $Prefix,

        [PSObject[]] $Subnets
    )
    
    $VirtualNetwork = $Context.ResourceGroup | Get-AzureVirtualNetwork -Name $Name -ErrorAction Ignore
    if ($VirtualNetwork -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: virtual network ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: create virtual network"
        $Count = 1
        $VirtualNetwork = $Context.ResourceGroup | New-AzureVirtualNetwork -Name $Name `
            -AddressPrefix $Prefix `
            -Subnet ($Subnets | % { New-AzureVirtualNetworkSubnetConfig -Name $_.Name -AddressPrefix $_.Prefix })
    }

    $Context | Add-Member -NotePropertyName VirtualNetwork -NotePropertyValue $VirtualNetwork
    return $Context
}

function Ensure-NetworkGateway
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name,

        [String] $PrivateIP
    )

    $Gateway = $Context.ResourceGroup | Get-AzureVirtualNetworkGateway -Name $Name -ErrorAction Ignore
    if ($Gateway -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: network gateway ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: create network gateway"
        $Subnet = $Context.VirtualNetwork.Subnets |? Name -eq "GatewaySubnet"
        $GatewayConfig = New-AzureVirtualNetworkGatewayIpConfig -Name ${Name}-config `
            -PublicIpAddress $Context.PublicIP -PrivateIpAddress $PrivateIP -Subnet $Subnet
        $Gateway = $Context.ResourceGroup | New-AzureVirtualNetworkGateway -Name $Name `
            -GatewayType Vpn `
            -VpnType RouteBased `
            -IpConfigurations $GatewayConfig
    }

    $Context | Add-Member -NotePropertyName NetworkGateway -NotePropertyValue $Gateway
    return $Context
}

function Ensure-NetworkSecurityGroup
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name,
        
        [Parameter(Mandatory)]
        [Hashtable[]] $Allow
    )

    $SecurityGroup = $Context.ResourceGroup | Get-AzureNetworkSecurityGroup -Name $Name -ErrorAction Ignore
    if ($SecurityGroup -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: network security group ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: new network security group"

        $Priority = 1000
        $AllowRules = $Allow |% { 
            New-AzureNetworkSecurityRuleConfig -Name $_.Name -Protocol $_.Proto -DestinationPortRange $_.Port -Priority $Priority -Direction Inbound -Access Allow `
                -DestinationAddressPrefix '*' -SourceAddressPrefix '*' -SourcePortRange '*'
            $Priority = $Priority + 1
        }
        $SecurityGroup = $Context.ResourceGroup | New-AzureNetworkSecurityGroup -Name $Name -SecurityRules $AllowRules
    }

    $Context | Add-Member -NotePropertyName SecurityGroup -NotePropertyValue $SecurityGroup
    return $Context
}

function Ensure-LoadBalancer
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name,

        [Parameter(Mandatory)]
        [PSObject[]] $Interfaces,

        [Parameter(Mandatory)]
        [PSObject[]] $LBRules
    )

    $LoadBalancer = $Context.ResourceGroup | Get-AzureLoadBalancer -Name $Name -Verbose -ErrorAction Ignore
    if ($LoadBalancer -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: load balancer ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: new load balancer"

        # create load balancer
        $LoadBalancer = $Context.ResourceGroup | New-AzureLoadBalancer -Name $Name `
            -FrontendIpConfiguration (New-AzureLoadBalancerFrontendIpConfig -Name ($Name + "-fe-ip") -PublicIpAddress $Context.PublicIP) `
            -BackendAddressPool (New-AzureLoadBalancerBackendAddressPoolConfig -Name ($Name + "-backendpool"))

        # add load balancing rules
        $Rules = $LBRules | % {
            $LoadBalancer = $LoadBalancer `
                | Add-AzureLoadBalancerRuleConfig -Name $_.Name `
                    -Protocol $_.Proto -FrontendPort $_.Src -BackendPort $_.Dst `
                    -BackendAddressPool $LoadBalancer.BackendAddressPools[0] `
                    -FrontendIpConfiguration $LoadBalancer.FrontendIpConfigurations[0] `
                | Set-AzureLoadBalancer
            $LoadBalancer.LoadBalancingRules[-1]
        }

        # add nat rules
        $Interfaces | % {
            $NatRules = $_.Nat | % {
                $LoadBalancer = $LoadBalancer `
                    | Add-AzureLoadBalancerInboundNatRuleConfig -Name $_.Name `
                        -Protocol $_.Proto -FrontendPort $_.Src -BackendPort $_.Dst `
                        -FrontendIpConfiguration $LoadBalancer.FrontendIpConfigurations[0] `
                    | Set-AzureLoadBalancer
                $LoadBalancer.InboundNatRules[-1]
            }
        }

        # create network interfaces
        $Interfaces | % {
            $Context.ResourceGroup | New-AzureNetworkInterface -Name $_.Name `
                -Subnet $Context.VirtualNetwork.Subnets[0] `
                -PrivateIPAddress $_.IP `
                -LoadBalancerBackendAddressPool $LoadBalancer.BackendAddressPools[0] `
                -LoadBalancerInboundNatRule ($_.Nat |% { $LoadBalancer | Get-AzureLoadBalancerInboundNatRuleConfig -Name $_.Name })
        } | Out-Null
    }

    $Context | Add-Member -NotePropertyName LoadBalancer -NotePropertyValue $LoadBalancer
    return $Context
}

function Ensure-NetworkInterface
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name,

        [Parameter(Mandatory)]
        [String] $PrivateIP
    )

    $NetworkInterface = $Context.ResourceGroup | Get-AzureNetworkInterface -Name $Name -ErrorAction Ignore
    if ($NetworkInterface -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: network interface ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: new network interface"
        $NetworkInterface = $Context.ResourceGroup | New-AzureNetworkInterface -Name $Name `
            -Subnet $Context.VirtualNetwork.Subnets[0] `
            -PublicIpAddress $Context.PublicIP `
            -PrivateIpAddress $PrivateIP `
            -NetworkSecurityGroup $Context.SecurityGroup
    }

    $Context | Add-Member -NotePropertyName NetworkInterface -NotePropertyValue $NetworkInterface
    return $Context
}

function Ensure-AvailabilitySet
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name
    )

    $AvailabilitySet = $Context.ResourceGroup | Get-AzureAvailabilitySet -Name $Name -ErrorAction Ignore
    if ($AvailabilitySet -ne $Null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: availability set ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: new availability set"
        $AvailabilitySet = $Context.ResourceGroup | New-AzureAvailabilitySet -Name $Name -PlatformFaultDomainCount 2 -PlatformUpdateDomainCount 2
    }

    $Context | Add-Member -NotePropertyName AvailabilitySet -NotePropertyValue $AvailabilitySet
    return $Context
}

function Ensure-VirtualMachine
{
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [PSObject] $Context,

        [Parameter(Mandatory)]
        [String] $Name,

        [Parameter(Mandatory)]
        [String] $VMSize,

        [Parameter(Mandatory)]
        [String] $DiskName,

        [Parameter(Mandatory)]
        [String] $NICName
    )

    $VM = $Context.ResourceGroup | Get-AzureVM -Name $Name -ErrorAction Ignore
    if ($VM -ne $null)
    {
        Write-Host -ForegroundColor Green "= ${Name}: virtual machine ok"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ ${Name}: new virtual machine"
        $VhdUri = $Context.StorageAccount.PrimaryEndpoints.Blob.ToString() + "vhds/" + $DiskName + ".vhd"
        $VMConfig = New-AzureVMConfig -VMName $Name -VMSize $VMSize -AvailabilitySetId $Context.AvailabilitySet.Id `
            | Set-AzureVMOperatingSystem -Linux -Credential $Context.Credential -ComputerName $Name `
            | Set-AzureVMSourceImage -PublisherName Canonical -Offer UbuntuServer -Skus 15.04 -Version "latest" `
            | Add-AzureVMNetworkInterface -Id ($Context.ResourceGroup | Get-AzureNetworkInterface -Name $NICName).Id `
            | Set-AzureVMOSDisk -Name $DiskName -VhdUri $VhdUri -CreateOption fromImage
        $Context.ResourceGroup | New-AzureVM -VM $VMConfig 
    }

    $Context | Add-Member -NotePropertyName VM -NotePropertyValue $VM
    return $Context
}

$Cr = New-Object PSCredential -ArgumentList @("jjm", (ConvertTo-SecureString "SuperGeheimWachtwoord1" -AsPlainText -Force))

#
# resource group jjm-jump
#

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-jump -Location WestEurope `
| Ensure-VirtualNetwork         -Name jjm-jump-vnet -Prefix 10.10.0.0/16 `
                                -Subnets @(
                                    @{name="jjm-jump-vnet-1"; prefix="10.10.0.0/24"},
                                    @{name="GatewaySubnet"; prefix="10.10.254.0/24"}) `
| Ensure-NetworkSecurityGroup   -Name ubuntu04-sg -Allow @(@{name="SSH"; proto="TCP"; port=22}) `
| Ensure-PublicIP               -Name ubuntu04-ip `
| Ensure-NetworkInterface       -Name ubuntu04-if -PrivateIP 10.10.0.104 | Out-Null

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-jump -Location WestEurope `
| Ensure-VirtualNetwork         -Name jjm-jump-vnet `
| Ensure-PublicIP               -Name jjm-jump-gw-ip `
| Ensure-NetworkGateway         -Name jjm-jump-gw -PrivateIP 10.10.254.4

Exit 1

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-jump -Location WestEurope `
| Ensure-AvailabilitySet        -Name jjm-jump-as `
| Ensure-StorageAccount         -Name jjmjump `
| Ensure-VirtualMachine         -Name ubuntu04 -VMSize Basic_A0 -DiskName ubuntu04 -NICName ubuntu04-nic | Out-Null


#
# resource group jjm-proxy
#

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-proxy -Location WestEurope `
| Ensure-VirtualNetwork         -Name jjm-proxy-vnet -Prefix 10.0.0.0/16 `
                                -Subnets @(
                                    @{name="jjm-proxy-vnet-1"; prefix="10.0.0.0/24"},
                                    @{name="GatewaySubnet"; prefix="10.0.254.0/24"}) `
| Ensure-NetworkSecurityGroup   -Name ubuntu01-sg -Allow @(
                                    @{name="SSH"; proto="TCP"; port=22},
                                    @{name="SSH-PROXY"; proto="*"; port=443}) `
| Ensure-PublicIP               -Name ubuntu01-ip `
| Ensure-NetworkInterface       -Name ubuntu01-if -PrivateIP 10.0.0.101 | Out-Null

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-proxy -Location WestEurope `
| Ensure-AvailabilitySet        -Name jjm-proxy-as `
| Ensure-StorageAccount         -Name jjmproxy `
| Ensure-VirtualMachine         -Name ubuntu01 -VMSize Basic_A0 -DiskName ubuntu01 -NICName ubuntu01-nic | Out-Null

#
# resource group jjm-dns-1
#

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-dns-1 -Location WestEurope `
| Ensure-VirtualNetwork         -Name jjm-dns-1-vnet -Prefix 10.1.0.0/16 `
                                -Subnets @(
                                    @{name="jjm-dns-1-vnet-1"; prefix="10.1.0.0/24"}) `
| Ensure-NetworkSecurityGroup   -Name ubuntu02-sg -Allow @(
                                    @{name="SSH"; proto="TCP"; port=22},
                                    @{name="DNS"; proto="*"  ; port=53}) `
| Ensure-PublicIP               -Name ubuntu02-ip `
| Ensure-NetworkInterface       -Name ubuntu02-nic -PrivateIP 10.1.0.102 | Out-Null

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-dns-1 -Location WestEurope `
| Ensure-AvailabilitySet        -Name jjm-dns-1-as `
| Ensure-StorageAccount         -Name jjmdnsa `
| Ensure-VirtualMachine         -Name ubuntu02 -VMSize Standard_A0 -DiskName ubuntu02 -NICName ubuntu02-nic | Out-Null

#
# resource group jjm-dns-2
#

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-dns-2 -Location WestUS `
| Ensure-VirtualNetwork         -Name jjm-dns-2-vnet -Prefix 10.2.0.0/16 `
                                -Subnets @(
                                    @{name="jjm-dns-2-vnet-1"; prefix="10.2.0.0/24"}) `
| Ensure-NetworkSecurityGroup   -Name ubuntu03-sg -Allow @(
                                    @{name="SSH"; proto="TCP"; port=22},
                                    @{name="DNS"; proto="*"  ; port=53}) `
| Ensure-PublicIP               -Name ubuntu03-ip `
| Ensure-NetworkInterface       -Name ubuntu03-nic -PrivateIP 10.2.0.103 | Out-Null

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-dns-2 -Location WestUS `
| Ensure-AvailabilitySet        -Name jjm-dns-2-as `
| Ensure-StorageAccount         -Name jjmdnsb `
| Ensure-VirtualMachine         -Name ubuntu03 -VMSize Standard_A0 -DiskName ubuntu03 -NICName ubuntu03-nic | Out-Null

#
# print public ip's
#

Get-AzurePublicIpAddress | select Name,IpAddress | sort Name | Format-Table