#!/bin/bash
# Add list locations to array
beginning_instructions="<list>etc/lists/"
list_names=("open_proxies" "datacenters_and_vpns" "firehol_level3" "firehol_level2" "alienvault_reputation" "tor_exits_7d" "c2" "china" "russia" "iran" "north_korea")
end_instructions="</list>"

# Instructions
add_to_ossec="    <!-- Threat Feed Lists -->\n"
for instruction in ${list_names[@]}; do
add_to_ossec+="    $beginning_instructions$instruction$end_instructions\n"
done

cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
sed "/<ruleset>/a \\$add_to_ossec" /var/ossec/etc/ossec.conf > /var/ossec/etc/ossec.conf.tmp
mv /var/ossec/etc/ossec.conf.tmp /var/ossec/etc/ossec.conf

# restart wazuh to apply changes
systemctl restart wazuh-manager
