<#
azure-nsg-flow-oms-upload.ps1
Jason Boeshart, Cloud Solution Architect, Microsoft
Apache 2.0 License

.SYNOPSIS
    Uploads NSG Flow Logs to an OMS workspace

.DESCRIPTION
    This script uploads NSG Flow Logs to an OMS workspace. Based on code found
    at https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api. 

.PARAMETER OmsWorkspaceId
    The OMS workspace ID as found in the OMS portal

.PARAMETER OmsSharedKey 
    The OMS Shared Key corresponding to the workspace ID

.PARAMETER OmsLogType
    The record type that you'll be uploading to

.PARAMETER StorageAccountName 
    Name of the storage account containing NSG flow logs

.PARAMETER StorageAccountKey
    Storage account key for the storage account with flow logs

.PARAMETER ContainerName
    Name of the container in the storage account containing NSG flow logs, optional
    and set to the standard default container created by Azure Network Watcher

.LINK
    https://github.com/jboeshart/azure-nsg-flow-oms-upload
    https://blogs.msdn.microsoft.com/cloud_solution_architect/2017/04/03/uploading-azure-nsg-flow-logs-to-oms/
#>


Param(
    [Parameter(Mandatory=$True)]
    [String] $OmsWorkspaceId,

    [Parameter(Mandatory=$True)]
    [String] $OmsSharedKey,

    [Parameter(Mandatory=$True)]
    [String] $OmsLogType,

    [Parameter(Mandatory=$True)]
    [String] $StorageAccountName,   

    [Parameter(Mandatory=$True, ParameterSetName="StorageAccountKey")]
    [String] $StorageAccountKey,

    [Parameter(Mandatory=$True, ParameterSetName="SasToken")]
    [String] $SasToken,

    [String] $ContainerName = "insights-logs-networksecuritygroupflowevent"
)

# Field with the created time for the records
$TimeStampField = "DateTime"
# Set epoch time for date calculations
$epoch = get-date "1/1/1970"

# Function to create the authorization signature
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Function to create and post the request
Function Post-OMSData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -fileName $fileName `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode

}

# Function to parse through the flow log and upload to OMS, function accepts a standard object
Function Submit-FlowData($nsgflowobject)
{
    $uploadErrors = 0
    foreach ($record in $nsgflowobject.records) {
        $time = $record.time
        $resourceId = $record.resourceId
        $splitresourceId = $resourceId.Split("/")
        $sub = $splitresourceId[2]
        $rg = $splitresourceId[4]
        $nsg = $splitresourceId[8]
        foreach ($property in $record.properties) {
            foreach ($flows in $property.flows) {
                $rule = $flows.rule
                foreach ($flows2 in $flows.flows) {
                    $mac = $flows2.mac
                    foreach ($flowTuples in $flows2.flowTuples) {
                        $splitflowTuples = $flowTuples.Split(",")
                        $dt = $epoch.AddSeconds($splitflowTuples[0]).ToUniversalTime().ToString()
                        $jsonObj = @{
                            SubscriptionId = $sub
                            ResourceGroup = $rg
                            NSG = $nsg
                            Rule = $rule
                            MAC = $mac
                            DateTime = $dt
                            SourceIp = $splitflowTuples[1]
                            DestinationIp = $splitflowTuples[2]
                            SourcePort = $splitflowTuples[3]
                            DestinationPort = $splitflowTuples[4]
                            TcpOrUdp = $splitflowTuples[5]
                            InOrOut = $splitflowTuples[6]
                            AllowOrDeny = $splitflowTuples[7]
                        }
                        $json = ConvertTo-Json $jsonObj
                        Write-Output "Submitting: " $json
                        $returnCode = Post-OMSData -customerId $OmsWorkspaceId -sharedKey $OmsSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $OmsLogType
                        Write-Output "Return code: $($returnCode)"
                        if ($returnCode -ne "200") {
                            $uploadErrors++
                        }
                    }
                }
            }
        }
    }
    if ($uploadErrors -eq 0){
        # All uploads were successful, update file metadata so we don't re-upload on subsequent script runs
        Write-Output "Return code 200 on all uploads, updating file metadata"
        $CloudBlockBlob = [Microsoft.WindowsAzure.Storage.Blob.CloudBlockBlob] $Blob.ICloudBlob
        $CloudBlockBlob.Metadata["OmsLogType"] = $OmsLogType
        $CloudBlockBlob.SetMetadata() 
    }
    else {
        # Had one or more errors during upload, log an error and move on
        Write-Output "One or more uploads had errors, please retry upload for file $($blob.Name)"
    }
}

# Loop through the storage and check the files
If ($StorageAccountKey) {
   $storageContext = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
}
elseif ($SasToken) {
   $storageContext = New-AzureStorageContext -StorageAccountName $StorageAccountName -SasToken $SasToken 
}

# Get all the blobs in the container.
$blobs = Get-AzureStorageBlob -Container $ContainerName -Context $storageContext

foreach ($blob in $blobs) {
    # Check to see if the year, month, day, and hour of the flow log (as defined in the blob name) match the current universal time values
    # If they match, it's the current file and we're going to leave it alone
    if ( -not (`
    (((Get-Date).ToUniversalTime() | Get-Date -UFormat %Y) -eq ($blob.Name.Split("/")[9].Split("=")[1])) -and `
    (((Get-Date).ToUniversalTime() | Get-Date -UFormat %m) -eq ($blob.Name.Split("/")[10].Split("=")[1])) -and `
    (((Get-Date).ToUniversalTime() | Get-Date -UFormat %d) -eq ($blob.Name.Split("/")[11].Split("=")[1])) -and `
    (((Get-Date).ToUniversalTime() | Get-Date -UFormat %H) -eq ($blob.Name.Split("/")[12].Split("=")[1]))))
    {
        # Check for metadata to see if it's already been uploaded to OMS
        if ($blob.ICloudBlob.Metadata.OmsLogType -ne $OmsLogType) {
            Write-Output "Processing file: $($blob.Name)"
            if ($StorageAccountKey) {
                # Download the file content locally, have to do this as there's currently no way to stick it straight into a variable with just the storage key
                Get-AzureStorageBlobContent -Container $ContainerName -Context $storageContext -Blob $blob.Name -Force -Destination .
                # Convert blob content from JSON to a standard object
                $blobcontent = Get-Content -Raw -Path $blob.Name | ConvertFrom-Json
                # Call function to process file and upload to OMS
                Submit-FlowData($blobcontent)
                # Remove the temp file
                Remove-Item $blob.Name
            }
            elseif ($SasToken) {
                # Download the blob content via HTTPS directly to a variable, we can do this because we have SAS token
                $blobcontent = Invoke-RestMethod -Uri  $($blob.ICloudBlob.Uri.ToString() + $SasToken)
                # Call function to process file and upload to OMS
                Submit-FlowData($blobcontent)
            }
        }
    }
    else {
        Write-Output "Not processing current file: $($blob.Name)"
    }
}
