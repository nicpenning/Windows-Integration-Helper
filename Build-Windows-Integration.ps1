#$testEventPowershellOperational = Get-WinEvent -LogName "Microsoft-Windows-Powershell/Operational" -MaxEvents 1000| Where-Object {$_.Id -eq 4103}
#$testEventAppLockerEXE = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 100000 | Where-Object {$_.Id -eq 8003}
#$testEventAppLockerMSI = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/MSI and Script" -MaxEvents 100000 | Where-Object {$_.Id -eq 8006}

# Copy latest integration into data stream directory
# Rename Copy to <new data stream by using channel name>
# Delete all files int _dev/test
# Copy over test-events from this script into that directory
# Update agent/stream/winlog.yml.hbs file with current Channel name
# Update elasticsearch/ingest_pipeline/default.yml with current Channel name
# Update base fields event.data constant keyword to windows.<data-stream-name>
# Update <data-stream>/manifest.yml file - Title, streams/title, streams/description, input/title, input/description, input/vars/name:search/default
# Delete sample_event.json
# Update Data Stream - manifest.yml, changelog.yml
# Generate test files with elastic-package test pipeline --data-streams <data-stream-name> --generate
# Generate sample_event file with elastic-package test system --data-streams <data-stream-name> --generate
# Update _dev/build/docs/README.md with new data stream information
# Update .github/CODEOWNERS with /packages/windows/data_stream/<data-stream-name @elastic/security-external-integrations
# Build the elastic-package
# Submit a PR once there are no errors and the events look valid and do not contain any sensitive information, user names, computer names, etc..

$customLogName = "Microsoft-Windows-AppLocker/Packaged app-Execution"
$customEvent = Get-WinEvent -LogName $customLogName -MaxEvents 100000

# Redacted Parameters
$redactedHostParameters = @("Finance-10", "WIN10")
$redactedUserParameters = @("DSCHRUTE", "USER75")
$redactedDomainParameters = @("schrute.farms.local", "local")

$customIdsFound = $customEvent.Id | Select-Object -Unique
Write-Host "All custom IDs"
$customIdsFound

# XML Event for HTTP JSON - _dev/deploy/docker/files/config.yml
$customEventXML = $(Get-WinEvent -LogName $customLogName -MaxEvents 1).ToXml()
#$customEventXMLEventObject = $([xml]$customEventXML).Event
$customEventXMLJSONEscaped = $customEventXML | ConvertTo-Json

$deployDockerFilesConfig_yml = @"
- path: /services/search/jobs/export
    user: test
    password: test
    methods:
      - post
    query_params:
      index_earliest: "{index_earliest:[0-9]+}"
      index_latest: "{index_latest:[0-9]+}"
      output_mode: json
      search: 'search sourcetype="XmlWinEventLog:$customLogName" | streamstats max(_indextime) AS max_indextime'
    request_headers:
      Content-Type:
        - "application/x-www-form-urlencoded"
    responses:
      - status_code: 200
        headers:
          Content-Type:
            - "application/json"
        body: |-
          {
              "preview": false,
              "offset": 194,
              "lastrow": true,
              "result": {
                  "_bkt": "main~0~1212176D-89E1-485D-89E6-3ADC276CCA38",
                  "_cd": "0:315",
                  "_indextime": "1622471463",
                  "_raw": $customEventXMLJSONEscaped,
                  "_serial": "194",
                  "_si": [
                      "69819b6ce1bd",
                      "main"
                  ],
                  "_sourcetype": "XmlWinEventLog:Security",
                  "_time": "2021-05-25 13:11:45.000 UTC",
                  "host": "VAGRANT",
                  "index": "main",
                  "linecount": "1",
                  "max_indextime": "1622471606",
                  "source": "WinEventLog:Security",
                  "sourcetype": "XmlWinEventLog:Security",
                  "splunk_server": "69819b6ce1bd"
              }
          }
"@

# Add the XML to config.yml
$configRawYML = $(Invoke-WebRequest "https://raw.githubusercontent.com/elastic/integrations/main/packages/windows/_dev/deploy/docker/files/config.yml").content
$configRawYML | Out-File config_new.yml
Add-Content -Path config_new.yml -Value $deployDockerFilesConfig_yml.Replace("$($redactedHostParameters[0])", "$($redactedHostParameters[1])").Replace("$($redactedDomainParameters[0])","$($redactedDomainParameters[1])") -NoNewline

# Get sample event IDs for pipeline tests
$pipelineSampleEventsPerEventID = @()
$customIdsFound | ForEach-Object {
    $eventId = $_
    $pipelineSampleEventsPerEventID += $([xml]$((Get-WinEvent -LogName $customLogName -MaxEvents 1 | Where-Object {$_.Id -eq $eventId}).ToXML())).Event
}

<# Get potential field names - To Do or Not To Do
$fieldNames = @()
$fieldNames += if($($pipelineSampleEventsPerEventID.UserData)){$pipelineSampleEventsPerEventID.UserData}else{$null}
$fieldNames += if($($pipelineSampleEventsPerEventID.EventData)){$pipelineSampleEventsPerEventID.EventData}else{$null}
$baseWinLogFields = ("ActivityId", "Id", "LevelDisplayName", "LogName", "MachineName", "OpcodeDisplayName", "ProcessId", "Properties", "RecordId", "TaskDisplayName", "ThreadId", "TimeCreated", "UserId", "Version")
$fieldsNotUsed = ("Bookmark", "ContainerLog", "Keywords", "KeywordsDisplayNames", "Level", "MatchedQueryIds", "Opcode", "Qualifiers", "RelatedActivityId", "Task")
#>
function Generate-WinLog-Object ($eventToParse) {
    # Get additional event log information for the event being parsed
    $time = $eventToParse.System.TimeCreated.SystemTime
    $customLogName = $eventToParse.System.Channel
    $xpath = @"
     <QueryList>
       <Query Id="0" Path="$customLogName">
         <Select Path="$customLogName">
           *[System[TimeCreated[@SystemTime='$time']]]    
         </Select>
       </Query>
     </QueryList>
"@
    $eventMetaData = Get-WinEvent -LogName $customLogName -FilterXPath $xpath
    $userName = $null
    #$userPrincipal = $null
    #$principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
    #$userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $eventMetaData.UserId.Value)
    $userName = "Topsy"

    # Create the User Data Object
    $userDataXMLElement = $eventToParse.UserData.RuleAndFileData
    $userDataObjects = [PSCustomObject]@{}
    foreach ($childNode in $userDataXMLElement.ChildNodes) {
        if ($childNode -is [System.Xml.XmlElement]) {
            $propertyName = $childNode.Name
            $propertyValue = $childNode.InnerText
            $userDataObjects | Add-Member -MemberType NoteProperty -Name $propertyName -Value $propertyValue
        }
    }

    [PSCustomObject]@{
        '@timestamp' = $eventToParse.System.TimeCreated.SystemTime
        event = [PSCustomObject]@{
            code = $eventMetaData.Id -replace "`0"
            kind = "event"
            provider = $eventMetaData.ProviderName -replace "`0"
        }
        host = [PSCustomObject]@{
            name = $eventMetaData.MachineName.Replace("$($redactedHostParameters[0])","$($redactedHostParameters[1])").Replace("$($redactedDomainParameters[0])","$($redactedDomainParameters[1])") -replace "`0"
        }
        log = [PSCustomObject]@{
            level = $eventMetaData.LevelDisplayName -replace "`0"
        }
        message = $eventMetaData.Message.Replace("$($redactedUserParameters[0])","$($redactedUserParameters[1])").Replace("$($redactedDomainParameters[0])","$($redactedDomainParameters[1])") -replace "`0"
        winlog = [PSCustomObject]@{
            activity_id = $eventMetaData.ActivityId.Guid -replace "`0"
            channel = $eventMetaData.LogName -replace "`0"
            computer_name = $eventMetaData.MachineName.Replace("$($redactedHostParameters[0])","$($redactedHostParameters[1])").Replace("$($redactedDomainParameters[0])","$($redactedDomainParameters[1])") -replace "`0"
            user_data = $userDataObjects
            event_id = $($eventMetaData.Id).ToString()
            level = $eventMetaData.LevelDisplayName -replace "`0"
            opcode = $eventMetaData.OpcodeDisplayName -replace "`0"
            process = [PSCustomObject]@{
                pid = [int]$($eventMetaData.ProcessId -replace "`0")
                thread = [PSCustomObject]@{
                    id = [int]$($eventMetaData.ThreadId -replace "`0")
                }
            }
            provider_guid = $eventMetaData.ProviderId.Guid -replace "`0"
            provider_name = $eventMetaData.ProviderName -replace "`0"
            record_id = $eventMetaData.RecordId -replace "`0"
            time_created = $eventToParse.System.TimeCreated.SystemTime #| Get-Date -Format "o" -AsUTC
            user = [PSCustomObject]@{
                identifier = $eventMetaData.UserId.Value -replace "`0"
                name = if($null -ne $userName){$userName.Replace("$($redactedUserParameters[0])","$($redactedUserParameters[1])") -replace "`0"}else{$null}
            }
            version = $eventMetaData.Version
            
        }
    }
}
Generate-WinLog-Object $pipelineSampleEventsPerEventID

$sampleEvent = Generate-WinLog-Object $pipelineSampleEventsPerEventID

# Generate test event json file
$events = [PSCustomObject]@{
    events = @($sampleEvent)
}
$fileNameForSampleEvent = "test-events-"+$($customLogName.Replace(' ','-')).Replace('/','-').ToLower()+".json"
$events | ConvertTo-Json -Depth 6 | Out-File $fileNameForSampleEvent 
