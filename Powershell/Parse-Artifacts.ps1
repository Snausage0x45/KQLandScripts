function Parse-Artifacts {
    param (
        [Parameter(Mandatory)]
        [string]$Drive,

        [Parameter(Mandatory)]
        [string]$outPath,

        [Parameter()]
        [string]$StartDate,

        [Parameter()]
        [string]$EndDate
    )
    
    #validate the drive exists
    if ($true -eq (Get-PSDrive -Name $Drive -ErrorAction SilentlyContinue)) {
        Write-Host "Using drive $Drive for processing" -BackgroundColor Green -ForegroundColor Black
    } else {
        Write-Host "Drive $Drive not found, please double check the mounted letter and ensure you are passing the letter only (pass I and not I:\)" -BackgroundColor Red -ForegroundColor Black
    }
    #set some Variables
    $linuxOutPath = wsl wslpath -u ($outpath.Replace('\','\\'))

    #make the log file
    if ($null -eq (Test-Path "$outPath\Parse-Artifacts_runLog.txt") ) {
        New-item -Name Parse-Artifacts_runLog.txt -Path $outPath
    }
    $logPath = $outPath + "/Parse-Artifacts_runLog.txt"

    $stopWatch = [System.Diagnostics.Stopwatch]::StartNew()

########################################################### Windows Events ###################################################################
    Add-Content -Path $logPath -Value "##################### Starting Windows Logs Section ###################################### `n"
    #Parse windows events with evtxECmd
    try {
        #create evtx path
        $evtxPath = $Drive + ":\" + "C\Windows\System32\winevt\logs"
        Write-host "Parsing windows event logs"
        & 'F:\tools\EvtxExplorer\EvtxECmd.exe' -d $evtxPath --csv $OutPath --csvf allEventLogsParsed.csv

        Add-Content -Path $logPath -Value "Successfully parsed all evtx logs in the supplied directory with EvtxECmd `n"
        
    }
    catch {
        Add-Content -Path $logPath -Value "Error with evtxecmd, please double check the output and try manually `n"
    }

    
    Write-Host "Finished parsing all windows logs, moving onto windows log detections `n"

    #Detect sus activity in windows logs with chainsaw
    try {
        #make chainsaw output folder
        if ($false -eq (test-path "$outPath\chainsawOutput")) {
            New-Item -ItemType Directory -Path $outPath -Name "chainsawOutPut"
        }else {
        }
        #create evtx path
        $evtxPath = $Drive + ":\" + "C\Windows\System32\winevt\logs"
        Write-host "Running chainsaw against windows logs"
        & "F:\tools\chainsaw\chainsaw.exe" hunt $evtxPath --rules F:\tools\chainsaw\sigma_rules --mapping F:\tools\chainsaw\mapping_files\sigma-mapping.yml --csv "$outPath\chainsawOutput" --lateral-all

        Add-Content -Path $logPath -Value "Successfully parsed all evtx logs in the supplied directory with chainsaw, output is in ($outPath + '\chainsawOutPut') `n"
    }
    catch {
        Add-Content -Path $logPath -Value "Error with chainsaw, please double check the output and try manually `n"
    }

    ###################################################### Evidence of Execution ###############################################################
    Add-Content -Path $logPath -Value "##################### Starting Evidence of Execution Section ###################################### `n"

    #Hash table of various EoE artifacts, can be expanded easily
    $EoEPathHash=@{
        "AmCache" = ("$drive" + ":\" + "C\Windows\AppCompat\Programs\Amcache.hve")
        "ShimCache" = ("$drive" + ":\" + "C\Windows\System32\config\SYSTEM")
        "Prefetch" = ("$drive" + ":\" + "c\Windows\prefetch\")
      }

    #Runs through each value, checks that the path or artifact is present then processes them if they exist 
    $EoEPathHash.GetEnumerator() | ForEach-Object {
        if ($true -eq (Test-Path $_.Value)) {
            $artifact = $_.Key.ToString()
            Write-host $artifact " was found, processing artifact" -ForegroundColor Black -BackgroundColor green
            Add-Content -Path $logPath -Value "$artifact Was found and will be processed `n"

            switch ($_.Key.ToString()) {
                AmCache { & "F:\tools\AmcacheParser.exe" -f ("$drive" + ":\" + "C\Windows\AppCompat\Programs\Amcache.hve") -w F:\tools\goodHashes.txt -i on --csv $outPath --csvf amcacheParsed.csv}
                ShimCache { & "F:\tools\AppCompatCacheParser.exe" -f("$drive" + ":\" + "C\Windows\System32\config\SYSTEM") --csv $outPath --csvf shimcacheParsed.csv }
                Prefetch { & 'F:\tools\PECmd.exe' -d ("$drive" + ":\" + "c\Windows\prefetch\") --csv $outPath --csvf prefetchParsed.csv }
            }

        }else {
            Write-Host "$artifact was not found and will be skipped" -ForegroundColor Black -BackgroundColor Yellow
            Add-Content -Path $logPath -Value "$artifact Was NOT found and won't be processed `n"
        }
        
    }

    try {
        $UserProfs = $drive + ":\" +"c\Users"
        if ($true -eq (test-path $UserProfs)) {
            & F:\tools\RegistryExplorer\RECmd.exe -d "$UserProfs" --bn F:\tools\RegistryExplorer\BatchExamples\AllRegExecutablesFoundOrRun.reb --csv $outPath --csvf AllRegExes.csv 
        }
    }
    catch {
    }
    
####################################### MFT Section #######################################
    Add-Content -Path $logPath -Value "##################### Starting MFT Section ###################################### `n"

    try {
        Write-Host "Parsing MFT"
        Add-Content -Path $logPath -Value " Parsed MFT items as CSV `n"
        #Parses the MFT in an item by item fashion
        & 'F:\tools\MFTECmd.exe' -f ("$Drive" + ":\" + 'C\$MFT') --csv $outPath --csvf "C_MFT_Parsed.csv"

    }
    catch {
    }

    try {
        #Creates a bodyfile then parses and outputs as a system timeline
        Write-Host "Creating bodyfile from MFT"
        Add-Content -Path $logPath -Value "Created bodyfile from MFT `n"
        & 'F:\tools\MFTECmd.exe' -f ("$Drive" + ":\" + 'C\$MFT') --body $outPath --bodyf "C_MFT_Timeline.body" --bld --bdl C:
    }
    catch {
        
    }

    try {
        $MFTbodyFileName = $linuxOutPath + "/C_MFT_Timeline.body"
        $mactimeMFTOutPath = $linuxOutPath + "/C_MFT_timeline.csv"
        
        Add-Content -Path $logPath -Value "Created MFT filesystem timeline  `n"
        wsl /bin/bash -c  "mactime -d -b $MFTbodyFileName -z UTC > $mactimeMFTOutPath"
    }
    catch {
        
    }
    
####################################################################### Super Timeline Section #########################################################
    Add-Content -Path $logPath -Value "##################### Starting Super Timeline Section ###################################### `n"

    try {

    $l2tDumpPath = $linuxOutPath + "/plaso.dump"
    $kapeVhdxLocation = (Get-volume -DriveLetter $Drive | Get-DiskImage | select ImagePath).ImagePath
    $kapeVhdxLocationDoubleWhack = $kapeVhdxLocation.replace('\','\\')
    $kapeVhdxLocationLinux = wsl wslpath $kapeVhdxLocationDoubleWhack

    Add-Content -Path $logPath -Value "Creating UTC body file from mounted VHDX `n"
    wsl /bin/bash -c "log2timeline.py -z UTC $l2tDumpPath $kapeVhdxLocationLinux"
    }catch{
    }


$l2tDumpPath = $linuxOutPath + "/plaso.dump"
    if ($false -eq $EndDate -or $null -eq $EndDate -and $null -eq $EndDate -or $false -eq $EndDate) {
        $Lt2FullPath = $linuxOutPath + "/C_Supertimeline.csv"
        wsl psort.py --output_time_zone UTC -o l2tcsv $l2tdumppath -w $Lt2FullPath

        Add-Content -Path $logPath -Value " Created full super-timeline with no date ranges `n"

    }elseif ($true -eq $StartDate -and $true -eq $EndDate) {
        $L2tSlicePath = $linuxOutPath + "/C_Supertimeline_" + $StartDate + "_" + $EndDate + "Slice" + ".csv"
         wsl psort.py --output_time_zone `'UTC`' -o l2tcsv $l2tdumppath "date > `'$startDate`' AND date < `'$endDate`'" -w $l2tslicepath
            
        Add-Content -Path $logPath -Value "Created super-timeline slice between dates $StartDate and $EndDate `n"
    }elseif ($false -eq $EndDate -or $null -eq $EndDate -and $true -eq $StartDate ) {
        $L2tSlicePath = $linuxOutPath + "/C_Supertimeline_" + "After_" +$StartDate + "Slice" + ".csv"
            
        wsl psort.py --output_time_zone UTC -o L2tcsv $l2tDumpPath "date > `'$startDate`'"  -w $l2tSlicePath

        Add-Content -Path $logPath -Value "Created super-timeline slice starting at $StartDate `n"

    }elseif ($false -eq $StartDate -or $null -eq $StartDate -and $true -eq $EndDate) {
        $L2tSlicePath = $linuxOutPath + "/C_Supertimeline_" + "Before_" + $EndDate + "Slice" + ".csv"
        
        wsl psort.py --output_time_zone UTC -o L2tcsv $l2tDumpPath "date < `'$endDate`'" -w $l2tSlicePath

        Add-Content -Path $logPath -Value "Created super-timeline slice ending on $EndDate `n"
    } 

    $stopWatch.Stop()
    $Runtime = $stopWatch.Elapsed.TotalMinutes.ToString()
    Add-Content -Path $logPath -Value "Script Exection took: $Runtime minutes to complete `n"
    
}
