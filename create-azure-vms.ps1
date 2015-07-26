
#Import-Module "C:\Program Files (x86)\Microsoft SDKs\Azure\PowerShell\ResourceManager\AzureResourceManager\AzureResourceManager.psd1"

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
        Write-Host -ForegroundColor Green "= Resource group $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Resource Group $Name"
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
        Write-Host -ForegroundColor Green "= Storage account $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Storage account $Name"
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
        Write-Host -ForegroundColor Green "= Public IP $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Public IP $Name"
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

        [Parameter(Mandatory)]
        [String] $Prefix,

        [Parameter(Mandatory)]
        [String[]] $Subnets
    )
    
    $VirtualNetwork = $Context.ResourceGroup | Get-AzureVirtualNetwork -Name $Name -ErrorAction Ignore
    if ($VirtualNetwork -ne $null)
    {
        Write-Host -ForegroundColor Green "= Virtual network $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Virtual network $Name"
        $Count = 1
        $VirtualNetwork = $Context.ResourceGroup | New-AzureVirtualNetwork -Name $Name `
            -AddressPrefix "10.0.0.0/16" `
            -Subnet ($Subnets | % { New-AzureVirtualNetworkSubnetConfig -Name ("subnet" + $Count++) -AddressPrefix $_ })
    }

    $Context | Add-Member -NotePropertyName VirtualNetwork -NotePropertyValue $VirtualNetwork
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
        Write-Host -ForegroundColor Green "= Security group $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Security group $Name"

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
        Write-Host -ForegroundColor Green "= Load balancer $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Load balancer $Name"

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
        [String] $Name
    )

    $NetworkInterface = $Context.ResourceGroup | Get-AzureNetworkInterface -Name $Name -ErrorAction Ignore
    if ($NetworkInterface -ne $null)
    {
        Write-Host -ForegroundColor Green "= Network interface $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Network interface $Name"
        $NetworkInterface = $Context.ResourceGroup | New-AzureNetworkInterface -Name $Name `
            -Subnet $Context.VirtualNetwork.Subnets[0] `
            -PublicIpAddress $Context.PublicIP `
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
        Write-Host -ForegroundColor Green "= Availability set $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Availability set $Name"
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
        Write-Host -ForegroundColor Green "= Virtual machine $Name"
    }
    else
    {
        Write-Host -ForegroundColor Yellow "+ Virtual machine $Name"
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
# resource group jjm-proxy
#

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup        -Name jjm-proxy -Location WestEurope `
| Ensure-AvailabilitySet      -Name jjm-proxy-as `
| Ensure-StorageAccount       -Name jjmproxy `
| Ensure-VirtualNetwork       -Name jjm-proxy-vnet -Prefix 10.0.0.0/16 -Subnets @("10.0.0.0/24") `
| Ensure-NetworkSecurityGroup -Name ubuntu01-sg -Allow @( @{ Name="SSH"; Proto="TCP"; Port=22 }, @{ Name="SSH-PROXY"; Proto="*"; Port=443 } ) `
| Ensure-PublicIP             -Name ubuntu01-ip `
| Ensure-NetworkInterface     -Name ubuntu01-if `
| Ensure-VirtualMachine       -Name ubuntu01 -VMSize Basic_A0 -DiskName ubuntu01 | Out-Null

#
# resource group jjm-dns-1
#

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup        -Name jjm-dns-1 -Location WestEurope `
| Ensure-AvailabilitySet      -Name jjm-dns-1-as `
| Ensure-StorageAccount       -Name jjmdnsa `
| Ensure-VirtualNetwork       -Name jjm-dns-1-vnet -Prefix 10.0.0.0/16 -Subnets @("10.0.0.0/24") `
| Ensure-NetworkSecurityGroup -Name ubuntu02-sg -Allow @( @{ Name="SSH"; Proto="TCP"; Port=22 }, @{ Name="DNS"; Proto="*"; Port=53 } ) `
| Ensure-PublicIP             -Name ubuntu02-ip `
| Ensure-NetworkInterface     -Name ubuntu02-if `
| Ensure-VirtualMachine       -Name ubuntu02 -VMSize Basic_A0 -DiskName ubuntu02| Out-Null

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup        -Name jjm-dns-1 -Location WestEurope `
| Ensure-AvailabilitySet      -Name jjm-dns-1-as `
| Ensure-StorageAccount       -Name jjmdnsa `
| Ensure-VirtualNetwork       -Name jjm-dns-1-vnet -Prefix 10.0.0.0/16 -Subnets @("10.0.0.0/24") `
| Ensure-NetworkSecurityGroup -Name ubuntu03-sg -Allow @( @{ Name="SSH"; Proto="TCP"; Port=22 }, @{ Name="DNS"; Proto="*"; Port=53 } ) `
| Ensure-PublicIP             -Name ubuntu03-ip `
| Ensure-NetworkInterface     -Name ubuntu03-if `
| Ensure-VirtualMachine       -Name ubuntu03 -VMSize Basic_A0 -DiskName ubuntu03| Out-Null

#
# resource group jjm-dns-2
#

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup        -Name jjm-dns-2 -Location WestUS `
| Ensure-AvailabilitySet      -Name jjm-dns-2-as `
| Ensure-StorageAccount       -Name jjmdnsb `
| Ensure-VirtualNetwork       -Name jjm-dns-2-vnet -Prefix 10.0.0.0/16 -Subnets @("10.0.0.0/24") `
| Ensure-NetworkSecurityGroup -Name ubuntu04-sg -Allow @( @{ Name="SSH"; Proto="TCP"; Port=22 }, @{ Name="DNS"; Proto="*"; Port=53 } ) `
| Ensure-PublicIP             -Name ubuntu04-ip `
| Ensure-NetworkInterface     -Name ubuntu04-if `
| Ensure-VirtualMachine       -Name ubuntu04 -VMSize Basic_A0 -DiskName ubuntu04| Out-Null

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup        -Name jjm-dns-2 -Location WestUS `
| Ensure-AvailabilitySet      -Name jjm-dns-2-as `
| Ensure-StorageAccount       -Name jjmdnsb `
| Ensure-VirtualNetwork       -Name jjm-dns-2-vnet -Prefix 10.0.0.0/16 -Subnets @("10.0.0.0/24") `
| Ensure-NetworkSecurityGroup -Name ubuntu05-sg -Allow @( @{ Name="SSH"; Proto="TCP"; Port=22 }, @{ Name="DNS"; Proto="*"; Port=53 } ) `
| Ensure-PublicIP             -Name ubuntu05-ip `
| Ensure-NetworkInterface     -Name ubuntu05-if `
| Ensure-VirtualMachine       -Name ubuntu05 -VMSize Basic_A0 -DiskName ubuntu05| Out-Null

#
# resource group jjm-dns-3 [experiment with load balancer]
#

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup          -Name jjm-dns-3 -Location WestEurope `
| Ensure-VirtualNetwork         -Name jjm-dns-3-vnet -Prefix 10.0.0.0/16 -Subnets @("10.0.0.0/24") `
| Ensure-PublicIP               -Name jjm-dns-3-lb-ip `
| Ensure-LoadBalancer           -Name jjm-dns-3-lb `
                                -Interfaces @( 
                                    @{ name="ubuntu02-nic"; 
                                       ip="10.0.0.102"; 
                                       nat=@(
                                            @{ name="jjm-dns-1-lb-nat-ssh-2"; proto="TCP"; src=2022; dst=22 },
                                            @{ name="jjm-dns-1-lb-nat-dns-2"; proto="UDP"; src=2053; dst=35353 })},
                                    @{ name="ubuntu03-nic";
                                       ip="10.0.0.103";
                                       nat=@(
                                            @{ name="jjm-dns-1-lb-nat-ssh-3"; proto="TCP"; src=3022; dst=22 },
                                            @{ name="jjm-dns-1-lb-nat-dns-3"; proto="UDP"; src=3053; dst=35353 })}) `
                                -LBRules @{ name="jjm-dns-1-lb-rule-dns"; proto="UDP"; src=53; dst=53 } | Out-Null

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup        -Name jjm-dns-3 -Location WestEurope `
| Ensure-AvailabilitySet      -Name jjm-dns-3-as `
| Ensure-StorageAccount       -Name jjmdnsc `
| Ensure-VirtualMachine       -Name ubuntu02 -VMSize Standard_A0 -DiskName ubuntu02 -NICName ubuntu02-nic | Out-Null

New-Object PSObject -Property @{ "Credential"=$Cr } `
| Ensure-ResourceGroup        -Name jjm-dns-3 -Location WestEurope `
| Ensure-AvailabilitySet      -Name jjm-dns-3-as `
| Ensure-StorageAccount       -Name jjmdnsc `
| Ensure-VirtualMachine       -Name ubuntu03 -VMSize Standard_A0 -DiskName ubuntu03 -NICName ubuntu03-nic | Out-Null

#
# print public ip's
#

Get-AzurePublicIpAddress | select Name,IpAddress | Format-Table