#!/bin/bash
tmp=$(mktemp)
echo "Using log file: $tmp"

./setup_s2e.exp | tee $tmp

mod_info=$(cat $tmp | grep -A 2 'MODULE INFORMATION' | tail -n 2)
#echo "$mod_info"

#size=$(echo $mod_info | grep Size | cut -d ':' -f 2)
#address=$(echo $mod_info | grep Address | cut -d ':' -f 2)

mod_size=$(echo "$mod_info" | grep "Size" | awk -F ':' '{print $2}')
mod_address=$(echo "$mod_info" | grep "Address" | awk -F ':' '{print $2}')

echo "[+] Modifying config.lua with Address: $mod_address and Size: $mod_size"


sed -i "s/^\snativebase = [[:alnum:]]*/nativebase = $mod_address/g" config.lua
sed -i "s/^\sstart = [[:alnum:]]*/start = $mod_address/g" config.lua
sed -i "s/^\ssize = [[:alnum:]]*/size = $mod_size/g" config.lua
sed -i "s/^\skernelStart = [[:alnum:]]*/skernelSart = $mod_address/g" config.lua

./run_s2e.exp | tee "S2E-LAST-LOG"
