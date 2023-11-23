#!/bin/bash

##################################################################################################
# THIS SCRIPT IS PROVIDED TO YOU "AS IS" TO THE EXTENT PERMITTED BY LAW, QUALYS AND TREND MICRO  #
# HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. IN NO   #
# EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS OR TREND MICRO. #
##################################################################################################

############# CONFIGURATION #############

# Trend Micro C1WS API key
export DS_apiKey='apikey'

# C1WS base URL - See available regions at: https://cloudone.trendmicro.com/docs/identity-and-account-management/c1-regions/
export DS_baseUrl='https://workload.YOUR-REGION.cloudone.trendmicro.com'

# Qualys credentials
export Q_user='username'
export Q_pass='password'

# Qualys API URLs - See available API endpoints at https://www.qualys.com/platform-identification/
export Q_qualysapiUrl='https://qualysapi.qg2.apps.qualys.eu'
export Q_gatewayUrl='https://gateway.qg2.apps.qualys.eu'

# Patching tasks, allowed values are yes/no
export deploy_missing_virtual_patches=yes

############# END OF CONFIGURATION #############

#### Common tasks Function ####
function common_tasks() {
# Creating authentication tokens for Qualys PM
export Q_tBody="username=$Q_user&password=$Q_pass&token=true&permissions=true"
export Q_token=$(curl -s -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "$Q_tBody" $Q_gatewayUrl/auth)

# Obtaining Deep Security ID for this host
export DS_hostId=$(/opt/ds_agent/sendCommand --get GetConfiguration | grep -oP "(?<=hostID=')((.|\n)*?)(?=')")
echo -------------------------------------------------------
echo "Deep Security ID: $DS_hostId"

# Obtaining Qualys Agent ID for this host to be used in PM and CAR
export Q_agentId=$(cat /etc/qualys/hostid)
echo "Qualys Agent ID:  $Q_agentId"

# Obtaining Qualys Host ID for this host to be used in VMDR and CSAM
export Q_hostId=$(curl -s -H "X-Requested-With: curl" -H "Content-Type: text/xml" -H "Cache-Control: no-cache" \
-u "$Q_user:$Q_pass" \
--data-binary @- "$Q_qualysapiUrl/qps/rest/2.0/search/am/hostasset/" < <(cat << EOF
<?xml version="1.0" encoding="UTF-8" ?>
<ServiceRequest>
 <filters>
  <Criteria field="agentUuid" operator="EQUALS">$Q_agentId</Criteria>
 </filters>
</ServiceRequest> 
EOF
) | grep -oP '(?<=<qwebHostId>)[^<]+')

echo "Qualys Host ID:   $Q_hostId"
echo -------------------------------------------------------
echo

# Adding the Deep Security ID as Custom Attribute in the Qualys asset
echo "Setting DS_hostID as Custom Attribute in Qualys asset:"

curl -s -H "X-Requested-With: curl" -H "Content-Type: text/xml" -H "Cache-Control: no-cache" \
-u "$Q_user:$Q_pass" \
--data-binary @- "$Q_qualysapiUrl/qps/rest/2.0/update/am/hostasset/" < <(cat << EOF
<?xml version="1.0" encoding="UTF-8" ?>
<ServiceRequest>
 <filters>
  <Criteria field="agentUuid" operator="EQUALS">$Q_agentId</Criteria>
 </filters>
<data>
 <HostAsset>
  <customAttributes>
   <add>
    <CustomAttribute>
     <key>DS_hostID</key>
     <value>$DS_hostId</value>
    </CustomAttribute>
   </add>
  </customAttributes>
 </HostAsset>
</data> 
</ServiceRequest>
EOF
) | grep -oP '(?<=<responseCode>)[^<]+'

echo
}

#### Vulnerability Queries Function ####
function vulnerability_queries() {
# Querying all the Virtual Patching rules applied to this host and saving them in ds_cve.txt
export DS_header1="Authorization: ApiKey $DS_apiKey"
export DS_header2="api-version: v1"
curl -s "$DS_baseUrl/api/computers/$DS_hostId/intrusionprevention/rules" \
     -H "$DS_header1" -H "$DS_header2" | grep -oP '(?<="CVE":\[)((.|\n)*?)(?=])' > ds_cve.txt
sed -i ':a;N;$!ba;s/\n/,/g; s/"//g' ds_cve.txt
export DS_vPatch=$(cat ds_cve.txt)

# Querying the QIDs of vulnerabilities detected by Qualys on this host and saving them in q_qid.txt
curl -s -X GET -u "$Q_user:$Q_pass" -H "X-Requested-With: curl" \
     "$Q_qualysapiUrl/api/2.0/fo/asset/host/vm/detection/?action=list&ids=$Q_hostId" \
| grep -oP '(?<=<QID>)[^<]+' > q_qid.txt
sed -i ':a;N;$!ba;s/\n/,/g; s/"//g' q_qid.txt
export Q_qid=$(cat q_qid.txt)

# Querying the CVEs associated to the QIDs detected in this host and saving them in q_cve.txt
curl -s -X GET -u "$Q_user:$Q_pass" -H "X-Requested-With: curl" \
     "$Q_qualysapiUrl/api/2.0/fo/knowledge_base/vuln/?action=list&ids=$Q_qid" \
| grep -oP '(?<=<ID><!\[CDATA\[)CVE-\d+[^]]+' > q_cve.txt
sed -i ':a;N;$!ba;s/\n/,/g; s/"//g' q_cve.txt

# Identifying CVEs detected by Qualys that are already being protected with Deep Security
comm -12 <(tr ',' '\n' < q_cve.txt | sort -u) <(tr ',' '\n' < ds_cve.txt | sort -u) > ds_protected.txt
export DS_pCount=$(cat ds_protected.txt | wc -l)
sed -i ':a;N;$!ba;s/\n/,/g; s/"//g' ds_protected.txt
export DS_protected=$(cat ds_protected.txt)

echo "$DS_pCount vulnerabilities detected by Qualys are currently protected by Deep Security:"
echo
echo "$DS_protected"
echo 

# Identifying CVEs detected by Qualys that Deep Security is not protecting
comm -32 <(tr ',' '\n' < q_cve.txt | sort -u) <(tr ',' '\n' < ds_cve.txt | sort -u) > ds_unprotected.txt
export DS_unpCount=$(cat ds_unprotected.txt | wc -l)
sed -i ':a;N;$!ba;s/\n/,/g; s/"//g' ds_unprotected.txt
export DS_unprotected=$(cat ds_unprotected.txt)

echo "$DS_unpCount vulnerabilities detected by Qualys are currently unprotected:"
echo
}

#### Search for missing Virtual Patching rules Function ####
function search_missing_vp_rules() {
# Checking if there are Virtual Patching rules for the rest of the vulnerabilities detected by Qualys and saving them in ds_newVP.txt
echo "Searching Virtual Patching rules for unprotected vulnerabilities. It may take few minutes..."
echo

sed -i 's/,/\n/g' ds_unprotected.txt

while read DS_unprotectedCve; do
  curl -s -X POST -H "$DS_header1" -H "$DS_header2" -H "Content-Type: application/json" -d '{
    "searchCriteria": [
     {
        "fieldName": "CVE",
        "stringTest": "equal",
        "stringValue": "'"${DS_unprotectedCve}"'"
      }
    ]
  }' "$DS_baseUrl/api/intrusionpreventionrules/search"
done < ds_unprotected.txt | grep -oP '(?<="ID":)[^,]*' > ds_newVP.txt

export DS_newVPCount=$(cat ds_newVP.txt | wc -l)
}

#### Deploy missing Virtual Patching rules Function ####
function deploy_missing_virtual_patches() {
# Add the Virtual Patching rules that are available for this host
echo "$DS_newVPCount Virtual Patching rules will be added to this host"
echo
sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/,/g' -i ds_newVP.txt
export DS_newVP=$(cat ds_newVP.txt)
echo $DS_newVP
echo
curl -s -X POST -H "$DS_header1" -H "$DS_header2" -H "Content-Type: application/json" -d '{
  "ruleIDs": [
    '"${DS_newVP}"'
  ]
}' "$DS_baseUrl/api/computers/$DS_hostId/intrusionprevention/assignments" > /dev/null
}

#### Removing temp files Function ####
function remove_temp_files() {
echo "Removing temporary files..."
echo
rm -f ds_*.txt q_*.txt
}

#### Start execution ####
cd /tmp
common_tasks
vulnerability_queries
search_missing_vp_rules

if [ "$deploy_missing_virtual_patches" = "yes" ]; then
  deploy_missing_virtual_patches
elif [ "$deploy_missing_virtual_patches" = "no" ]; then
  echo
  echo "No virtual patches will be deployed."
  echo
else echo
     echo "Invalid option for deploy_missing_virtual_patches variable"
     echo
fi

remove_temp_files
#### End execution ####
