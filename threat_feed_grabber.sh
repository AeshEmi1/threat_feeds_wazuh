#!/bin/bash
# Create temp directory for threat feed lists
mkdir -p /tmp/threat_feed_lists
rm -r /tmp/threat_feed_lists/*

# Download latest IP Reputation lists
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/proxylists_7d.ipset -o /tmp/threat_feed_lists/open_proxies.ipset
curl https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt -o /tmp/threat_feed_lists/datacenters_and_vpns.ipset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level3.netset -o /tmp/threat_feed_lists/firehol_level3.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset -o /tmp/threat_feed_lists/firehol_level2.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset -o /tmp/threat_feed_lists/alienvault_reputation.ipset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/tor_exits_7d.ipset -o /tmp/threat_feed_lists/tor_exits.ipset
curl -k https://216.128.135.134/threat_feeds/tor_exits.ipset -o /tmp/threat_feed_lists/tor_exits_dan.ipset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/cybercrime.ipset -o /tmp/threat_feed_lists/c2.ipset

# Country Lists
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_cn.netset -o /tmp/threat_feed_lists/china.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_ru.netset -o /tmp/threat_feed_lists/russia.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_ir.netset -o /tmp/threat_feed_lists/iran.netset
curl https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/geolite2_country/country_kp.netset -o /tmp/threat_feed_lists/north_korea.netset

# Download wazuh converter tool
curl https://raw.githubusercontent.com/AeshEmi1/threat_feeds_wazuh/main/iplist-to-cdblist.py -o /tmp/iplist-to-cdblist.py

# Combine TOR lists
sort -u /tmp/threat_feed_lists/tor_exits.ipset /tmp/threat_feed_lists/tor_exits_dan.ipset > /tmp/threat_feed_lists/tor_exits_7d.ipset

# Convert lists
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/open_proxies.ipset /tmp/threat_feed_lists/open_proxies
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/datacenters_and_vpns.ipset /tmp/threat_feed_lists/datacenters_and_vpns
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/firehol_level3.netset /tmp/threat_feed_lists/firehol_level3
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/firehol_level2.netset /tmp/threat_feed_lists/firehol_level2
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/alienvault_reputation.ipset /tmp/threat_feed_lists/alienvault_reputation
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/tor_exits_7d.ipset /tmp/threat_feed_lists/tor_exits_7d
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/c2.ipset /tmp/threat_feed_lists/c2

# Convert Country Lists
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/china.netset /tmp/threat_feed_lists/china
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/russia.netset /tmp/threat_feed_lists/russia
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/iran.netset /tmp/threat_feed_lists/iran
/var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /tmp/threat_feed_lists/north_korea.netset /tmp/threat_feed_lists/north_korea

# Remove unformatted lists and tool
rm -f /tmp/threat_feed_lists/open_proxies.ipset
rm -f /tmp/threat_feed_lists/datacenters_and_vpns.ipset
rm -f /tmp/threat_feed_lists/firehol_level3.netset
rm -f /tmp/threat_feed_lists/firehol_level2.netset
rm -f /tmp/threat_feed_lists/alienvault_reputation.ipset
rm -f /tmp/threat_feed_lists/tor_exits_7d.ipset
rm -f /tmp/threat_feed_lists/tor_exits.ipset
rm -f /tmp/threat_feed_lists/tor_exits_dan.ipset
rm -f /tmp/threat_feed_lists/c2.ipset

# Remove raw country list
rm -f /tmp/threat_feed_lists/china.netset
rm -f /tmp/threat_feed_lists/russia.netset
rm -f /tmp/threat_feed_lists/iran.netset
rm -f /tmp/threat_feed_lists/north_korea.netset

# Remove tool
rm -f /tmp/iplist-to-cdblist.py

# Fix permissions
chown wazuh:wazuh /tmp/threat_feed_lists/open_proxies
chown wazuh:wazuh /tmp/threat_feed_lists/datacenters_and_vpns
chown wazuh:wazuh /tmp/threat_feed_lists/firehol_level3
chown wazuh:wazuh /tmp/threat_feed_lists/firehol_level2
chown wazuh:wazuh /tmp/threat_feed_lists/alienvault_reputation
chown wazuh:wazuh /tmp/threat_feed_lists/tor_exits_7d
chown wazuh:wazuh /tmp/threat_feed_lists/c2
chown wazuh:wazuh /tmp/threat_feed_lists/china
chown wazuh:wazuh /tmp/threat_feed_lists/russia
chown wazuh:wazuh /tmp/threat_feed_lists/iran
chown wazuh:wazuh /tmp/threat_feed_lists/north_korea

# Add list locations to array
beginning_instructions="<list>etc/lists/"
list_names=($(ls /tmp/threat_feed_lists/))
end_instructions="</list>"

# Instructions
add_to_ossec="    <!-- Threat Feed Lists -->\n"
for instruction in ${list_names[@]}; do
add_to_ossec+="    $beginning_instructions$instruction$end_instructions\n"
done
add_to_ossec+="    <!-- Threat Feed Lists END -->"

if [ $(grep -c '<!-- Threat Feed Lists -->' "/var/ossec/etc/ossec.conf") -ge 1 ]; then
    sed -i '/<!-- Threat Feed Lists -->/,/<!-- Threat Feed Lists END -->/d' /var/ossec/etc/ossec.conf
fi
sed -i "/<ruleset>/a \\$add_to_ossec" /var/ossec/etc/ossec.conf

mv /tmp/threat_feed_lists/* /var/ossec/etc/lists

# restart wazuh to apply changes
systemctl restart wazuh-manager
