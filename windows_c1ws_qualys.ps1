##################################################################################################
# THIS SCRIPT IS PROVIDED TO YOU "AS IS" TO THE EXTENT PERMITTED BY LAW, QUALYS AND TREND MICRO  #
# HEREBY DISCLAIMS ALL WARRANTIES AND LIABILITY FOR THE PROVISION OR USE OF THIS SCRIPT. IN NO   #
# EVENT SHALL THESE SCRIPTS BE DEEMED TO BE CLOUD SERVICES AS PROVIDED BY QUALYS OR TREND MICRO. #
##################################################################################################

############# CONFIGURATION #############

# Trend Micro C1WS API key
$DS_apiKey = 'apikey'

# C1WS base URL - See regions at: https://cloudone.trendmicro.com/docs/identity-and-account-management/c1-regions/
$DS_baseUrl = 'https://workload.YOUR-REGION.cloudone.trendmicro.com'

# Qualys credentials
$Q_user = 'username'
$Q_pass = 'password'

# Qualys API URLs - See endpoints at https://www.qualys.com/platform-identification/
$Q_qualysapiUrl = 'https://qualysapi.qg2.apps.qualys.eu'
$Q_gatewayUrl = 'https://gateway.qg2.apps.qualys.eu'

# Patching tasks, allowed values are yes/no
$deploy_missing_virtual_patches = 'yes'

############# END OF CONFIGURATION #############

#### Common tasks ####
[Net.ServicePointManager]::SecurityProtocol = "Tls, Tls11, Tls12"
mkdir C:\Temp -erroraction 'silentlycontinue'
cd "C:\Program Files\Trend Micro\Deep Security Agent\"

# Creating Base64-encoded Qualys credentials
$Q_pairCreds = "$($Q_user):$($Q_pass)"
$Q_encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Q_pairCreds))

# Creating authentication tokens for Qualys PM
$Q_tHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Q_tHeaders.Add("Content-Type", "application/x-www-form-urlencoded")
$Q_tBody = "username=$Q_user&password=$Q_pass&token=true&permissions=true"
$Q_token = Invoke-RestMethod $Q_gatewayUrl/auth -Method 'POST' -Headers $Q_tHeaders -Body $Q_tBody

# Headers for conenecting to Deep Security API
$DS_headers = @{"Authorization"="ApiKey $DS_apiKey";"api-version"="v1";"Content-Type"="application/json";"Accept"="application/json"}

# Obtaining Deep Security ID for this host
$DS_hostId = .\sendCommand --get GetConfiguration | Select-String -Pattern "(?<=hostID=')((.|\n)*?)(?=')" | % { $_.Matches.Value }

Write-Output -------------------------------------------------------
Write-Output "Deep Security ID: $DS_hostId"

# Obtaining Qualys Agent ID for this host to be used in PM and CAR
$Q_agentId = (Get-ItemProperty "HKLM:\Software\Qualys" -Name "HostID").HostID
Write-Output "Qualys Agent ID:  $Q_agentId"

# Obtaining Qualys Host ID for this host to be used in VMDR and CSAM
$Q_headers1 = @{"X-Requested-With"="powershell";"Content-Type"= "application/xml";"Authorization"="Basic $Q_encodedCreds"}
$Q_body1 = @"
<?xml version="1.0" encoding="UTF-8" ?>
<ServiceRequest>
    <filters>
        <Criteria field="agentUuid" operator="EQUALS">$Q_agentId</Criteria>
    </filters>
</ServiceRequest>
"@

$Q_hostId = Invoke-WebRequest -Uri "$Q_qualysapiUrl/qps/rest/2.0/search/am/hostasset/" -UseBasicParsing -Method POST -Headers $Q_headers1 -Body $Q_body1 | select-String -Pattern '(?<=<qwebHostId>)[^<]+' -AllMatches | % { $_.Matches.Value }

Write-Output "Qualys Host ID:   $Q_hostId"
Write-Output -------------------------------------------------------
Write-Output ""

# Adding the Deep Security ID as Custom Attribute in the Qualys asset
$Q_body2 = @"
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
"@

Write-Output "Setting DS_hostID as Custom Attribute in Qualys asset:"
Invoke-WebRequest -Uri "$Q_qualysapiUrl/qps/rest/2.0/update/am/hostasset/" -UseBasicParsing -Method POST -Headers $Q_headers1 -Body $Q_body2 | select-String -Pattern '(?<=<responseCode>)[^<]+' -AllMatches | % { $_.Matches.Value }
Write-Output ""


#### Vulnerability Queries Function ####
function vulnerability_queries {
# Querying all the Virtual Patching rules applied to this host and saving them in C:\Temp\ds_cve.txt
Invoke-RestMethod "$DS_baseUrl/api/computers/$DS_hostId/intrusionprevention/rules" -Headers $DS_headers | ConvertTo-Json | Select-String -Pattern "(?<=`"CVE`":\s*`")((.|\n)*?)(?=`")" -AllMatches | % { $_.Matches.Value } > C:\Temp\ds_cve.txt
(get-content C:\Temp\ds_cve.txt) -join " " | foreach-object {$_ -replace " ", ","} | set-content C:\Temp\ds_cve.txt
$DS_vPatch=get-content C:\Temp\ds_cve.txt

# Querying the QIDs of vulnerabilities detected by Qualys on this host and saving them in C:\Temp\q_qid.txt
Invoke-WebRequest -Uri "$Q_qualysapiUrl/api/2.0/fo/asset/host/vm/detection/?action=list&ids=$Q_hostId" -UseBasicParsing -Headers $Q_headers1 | select-String -Pattern '(?<=<QID>)[^<]+' -AllMatches | % { $_.Matches.Value } > C:\Temp\q_qid.txt
(get-content C:\Temp\q_qid.txt) -join " " | foreach-object {$_ -replace " ", ","} | set-content C:\Temp\q_qid.txt
$Q_qid=get-content C:\Temp\q_qid.txt

# Querying the CVEs associated to the QIDs detected in this host and saving them in C:\Temp\q_cve.txt
Invoke-WebRequest -Uri "$Q_qualysapiUrl/api/2.0/fo/knowledge_base/vuln/?action=list&ids=$Q_qid" -UseBasicParsing -Headers $Q_headers1 | select-String -Pattern '(?<=<ID><!\[CDATA\[)CVE-\d+[^]]+' -AllMatches | % { $_.Matches.Value } > C:\Temp\q_cve.txt
(get-content C:\Temp\q_cve.txt) -join " " | foreach-object {$_ -replace " ", ","} | set-content C:\Temp\q_cve.txt

# Identifying CVEs detected by Qualys that are already being protected with Deep Security
$q_cve_tmp = Get-Content C:\Temp\q_cve.txt | % { $_ -split ',' } | Select-Object -Unique
$ds_cve_tmp = Get-Content C:\Temp\ds_cve.txt | % { $_ -split ',' } | Select-Object -Unique
Compare-Object $q_cve_tmp $ds_cve_tmp -IncludeEqual -ExcludeDifferent | % { $_.InputObject } > C:\Temp\ds_protected.txt

$DS_pCount = Get-Content C:\Temp\ds_protected.txt | Measure-Object -Line | Select-Object -ExpandProperty Lines
(get-content C:\Temp\ds_protected.txt) -join " " | foreach-object {$_ -replace " ", ","} | set-content C:\Temp\ds_protected.txt
$DS_protected = Get-Content C:\Temp\ds_protected.txt

Write-Output "$DS_pCount vulnerabilities detected by Qualys are currently protected by Deep Security:"
Write-Output ""
Write-Output "$DS_protected"
Write-Output ""

# Identifying CVEs detected by Qualys that Deep Security is not protecting
Compare-Object -ReferenceObject $q_cve_tmp -DifferenceObject $ds_cve_tmp | Where-Object { $_.SideIndicator -eq '<=' } | Select-Object -ExpandProperty InputObject > ds_unprotected.txt
$DS_unpCount = Get-Content ds_unprotected.txt | Measure-Object -Line | Select-Object -ExpandProperty Lines

Write-Output "$DS_unpCount vulnerabilities detected by Qualys are currently unprotected:"
Write-Output ""


#### Search for missing Virtual Patching rules Function ####

# Checking if there are Virtual Patching rules for the rest of the vulnerabilities detected by Qualys and saving them in C:\Temp\ds_newVP.txt
Write-Output "Searching Virtual Patching rules for unprotected vulnerabilities. It may take few minutes..."
Write-Output ""

$DS_unprotectedCve = Get-Content ds_unprotected.txt
$DS_response = foreach ($DS_responseCve in $DS_unprotectedCve) {
    $DS_responseBody = @"
{
    "searchCriteria": [
        {
            "fieldName": "CVE",
            "stringTest": "equal",
            "stringValue": "$DS_responseCve"
        }
    ]
}
"@

    Invoke-RestMethod -Uri "$DS_baseUrl/api/intrusionpreventionrules/search"  -Method POST -Headers $DS_headers -Body $DS_responseBody | ConvertTo-Json
 }
$DS_response | Select-String -Pattern '(?<="ID":\s*)[^,]*' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value | Out-File -FilePath C:\Temp\ds_newVP.txt
}

#### Deploy missing Virtual Patching rules Function ####
function deploy_missing_virtual_patches {
# Add the Virtual Patching rules that are available for this host
$DS_newVPCount = Get-Content C:\Temp\ds_newVP.txt | Measure-Object -Line | Select-Object -ExpandProperty Lines
Write-Output "$DS_newVPCount Virtual Patching rules will be added to this host"
Write-Output ""

(Get-Content C:\Temp\ds_newVP.txt) -replace '\s+' | Out-File C:\Temp\ds_newVP.txt
(Get-Content C:\Temp\ds_newVP.txt) -join " " | foreach-object {$_ -replace " ", ","} | set-content C:\Temp\ds_newVP.txt

$DS_newVP = Get-Content C:\Temp\ds_newVP.txt
Write-Output "$DS_newVP"
Write-Output ""
$DS_newVPBody =  @"
{
  "ruleIDs": [
    $DS_newVP
  ]
}
"@

Invoke-RestMethod -Uri "$DS_baseUrl/api/computers/$DS_hostId/intrusionprevention/assignments" -Method POST -Headers $DS_headers -Body $DS_newVPBody
Write-Output ""
}

#### Removing temp files Function ####
function remove_temp_files {
Write-Output "Removing temporary files..."
Write-Output ""
Remove-Item C:\Temp\ds_*.txt, C:\Temp\q_*.txt
}

#### Start execution ####
vulnerability_queries

if ($deploy_missing_virtual_patches -eq "yes") {
  deploy_missing_virtual_patches
}
elseif ($deploy_missing_virtual_patches -eq "no") {
  Write-Output ""
  Write-Output "No virtual patches will be deployed."
  Write-Output ""
}
else {
  Write-Output ""
  Write-Output "Invalid option for deploy_missing_virtual_patches variable"
  Write-Output ""
}

remove_temp_files
#### End execution ####
