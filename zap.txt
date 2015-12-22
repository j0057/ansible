umount -R /mnt
swapoff -a
lsblk -P \
    | sed -rn '/TYPE="crypt"/ { s/^NAME="([^ ]*)" .*$/\1/ ; p }' \
    | xargs -n 1 cryptsetup close
rm -rfv /tmp/crypttab /tmp/luks.keys
