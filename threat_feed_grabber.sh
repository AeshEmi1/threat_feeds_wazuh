#!/bin/bash
# Be sure to edit ossec.conf MANUALLY
# Download latest IP Reputation lists
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxylists_7d.ipset -o /var/ossec/etc/lists/open_proxies.ipset
curl https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt -o /var/ossec/etc/lists/datacenters_and_vpns.ipset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset -o /var/ossec/etc/lists/firehol_level3.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset -o /var/ossec/etc/lists/firehol_level2.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset -o /var/ossec/etc/lists/alienvault_reputation.ipset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits_7d.ipset -o /var/ossec/etc/lists/tor_exits.ipset
curl -k https://216.128.135.134/threat_feeds/tor_exits.ipset -o /var/ossec/etc/lists/tor_exits_dan.ipset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset -o /var/ossec/etc/lists/c2.ipset

# Country Lists
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_cn.netset -o /var/ossec/etc/lists/china.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_ru.netset -o /var/ossec/etc/lists/russia.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_ir.netset -o /var/ossec/etc/lists/iran.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_kp.netset -o /var/ossec/etc/lists/north_korea.netset

# Download wazuh converter tool
curl https://wazuh.com/resources/iplist-to-cdblist.py -o /tmp/iplist-to-cdblist.py

# Combine TOR lists
sort -u /var/ossec/etc/lists/tor_exits.ipset /var/ossec/etc/lists/tor_exits_dan.ipset > /var/ossec/etc/lists/tor_exits_7d.ipset

# Convert lists
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/open_proxies.ipset /var/ossec/etc/lists/open_proxies
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/datacenters_and_vpns.ipset /var/ossec/etc/lists/datacenters_and_vpns
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/firehol_level3.netset /var/ossec/etc/lists/firehol_level3
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/firehol_level2.netset /var/ossec/etc/lists/firehol_level2
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/alienvault_reputation
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/tor_exits_7d.ipset /var/ossec/etc/lists/tor_exits_7d
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/c2.ipset /var/ossec/etc/lists/c2

# Convert Country Lists
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/china.netset /var/ossec/etc/lists/china
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/russia.netset /var/ossec/etc/lists/russia
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/iran.netset /var/ossec/etc/lists/iran
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/north_korea.netset /var/ossec/etc/lists/north_korea

# Remove unformatted lists and tool
rm -f /var/ossec/etc/lists/open_proxies.ipset
rm -f /var/ossec/etc/lists/datacenters_and_vpns.ipset
rm -f /var/ossec/etc/lists/firehol_level3.netset
rm -f /var/ossec/etc/lists/firehol_level2.netset
rm -f /var/ossec/etc/lists/alienvault_reputation.ipset
rm -f /var/ossec/etc/lists/tor_exits_7d.ipset
rm -f /var/ossec/etc/lists/tor_exits.ipset
rm -f /var/ossec/etc/lists/tor_exits_dan.ipset
rm -f /var/ossec/etc/lists/c2.ipset

# Remove raw country list
rm -f /var/ossec/etc/lists/china.netset
rm -f /var/ossec/etc/lists/russia.netset
rm -f /var/ossec/etc/lists/iran.netset
rm -f /var/ossec/etc/lists/north_korea.netset

# Remove tool
rm -f /tmp/iplist-to-cdblist.py

# Fix permissions
chown wazuh:wazuh /var/ossec/etc/lists/open_proxies
chown wazuh:wazuh /var/ossec/etc/lists/datacenters_and_vpns
chown wazuh:wazuh /var/ossec/etc/lists/firehol_level3
chown wazuh:wazuh /var/ossec/etc/lists/firehol_level2
chown wazuh:wazuh /var/ossec/etc/lists/alienvault_reputation
chown wazuh:wazuh /var/ossec/etc/lists/tor_exits_7d
chown wazuh:wazuh /var/ossec/etc/lists/c2
chown wazuh:wazuh /var/ossec/etc/lists/china
chown wazuh:wazuh /var/ossec/etc/lists/russia
chown wazuh:wazuh /var/ossec/etc/lists/iran
chown wazuh:wazuh /var/ossec/etc/lists/north_korea

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
