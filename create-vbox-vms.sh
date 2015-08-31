#!/bin/bash

BASE="$HOME/VirtualBox VMs"
DVD="$HOME/ISOs"

#for x in zencfg1d ; do 
#    vboxmanage showvminfo $x &> /dev/null && vboxmanage unregistervm $x --delete &> /dev/null
#    rm -rf "$BASE/$x"
#done
#find "$BASE"

ensure-vm() {
    local vmname=$1
    local cpucount=$2
    local ram=$3
    local vram=$4
    local ostype=$5
    if vboxmanage showvminfo "$vmname" &> /dev/null; then
        echo "$vmname: found vm"
    else
        echo "$vmname: creating vm"
        vboxmanage createvm --name $vmname --ostype $ostype --register
        vboxmanage modifyvm $vmname --cpus $cpucount
        vboxmanage modifyvm $vmname --memory $ram
        vboxmanage modifyvm $vmname --vram $vram
        vboxmanage storagectl $vmname --name SATA --add sata
    fi
}

ensure-disk() {
    local vmname=$1
    local disktype=$2
    local disknum=$3
    local diskname=$2
    local disksize=$4

    case $disktype in
        hdd)
            local filename="${BASE}/${vmname}/${diskname}"

            # create medium
            if [ -f "$filename" ]; then
                echo "$vmname: found disk $diskname"
            else
                echo "$vmname: creating disk $diskname"
                vboxmanage createmedium disk --filename "$filename" --size $disksize
            fi

            # attach disk
            if vboxmanage showmediuminfo "$filename" | grep "In use by VMs" &> /dev/null; then
                echo "$vmname: attached disk $diskname"
            else
                echo "$vmname: attaching disk $diskname"
                vboxmanage storageattach $vmname --storagectl "SATA" --device 0 --port $disknum --type hdd --medium "$filename"
            fi
            ;;

        dvd)
            ;;
}

#           vmname      cpucount    ram     vram    ostype
ensure-vm   zencfg1d    1           2048    12      RedHat_64

#           vmname      type    #   diskname                                        size
ensure-disk zencfg1d    hdd     0   zencfg1d.vdi                                    16384
ensure-disk zencfg1d    dvd     1   CentOS-6.5-x86_64-minimal.iso
ensure-disk zencfg1d    dvd     2   en_windows_server_2012_r2_x64_dvd_2707946.iso
