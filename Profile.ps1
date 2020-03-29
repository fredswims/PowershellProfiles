"*** Version::2020-03-28.2"
#ShowSpeedTest;fsayit
# Identify this profile
#$ProfileNames ="AllUsersAllHosts", "AllUsersCurrentHost", "CurrentUserAllHosts", "CurrentUserCurrentHost"
$ProfileNames = ($profile|Get-Member -membertype noteproperty).name
$count = 0
($ProfileNames).foreach( {if ($PSCommandPath -eq $($Profile.$_)) {$Temp ="profile [{0}] with path {1}" -f $_, $PSCommandPath ; $Count++}})
write-warning "Start of $($Temp)"
If ($count -ne 1) {write-host -foregroundColor 'red' "Which profile is this?"}
if ([Environment]::Is64BitProcess){"*** Is 64 bit process"}else {"*** Is 32 bit process"}
if ($IsCoreClr) {"Running Pwsh"} else {"Running Powershell"}
"Profile specific code starts here"
# "C:\ProgramData\Quicken\config\QUICKEN.INI"


# New-Item -ItemType SymbolicLink -Path "Link" -Target "Target"
# https://winaero.com/blog/create-symbolic-link-windows-10-powershell/
# remove a link --- (Get-Item C:\SPI).Delete()
# added start-process to function showSwimClubFTP
# function Show-BackItUp
# 2019-12-31 Quicken using Pwsh-Preview
#
#ShowWindowsComputerInfo
"*** PSVersionTable"
$PSVersionTable
get-executionPolicy -list |Format-Table
<#
Somethings to remember

About logging
https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-6
https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html
Stuff controlled in the registry
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
Similar to GPEDIT.msc
Administrative Templates\Windows Components\Windows Powershell

This command sets an execution policy of AllSigned for only the current Windows PowerShell session.
This execution policy is saved in the PSExecutionPolicyPreference
environment variable ($env:PSExecutionPolicyPreference),
so it does not affect the value in the registry.
The variable and its value are deleted when the current session is closed.
https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Security/Set-ExecutionPolicy?view=powershell-5.1
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Unrestricted -Force
Set-ExecutionPolicy -Scope Process -ExecutionPolicy AllSigned or Unrestricted
get-executionPolicy -list | format-table

Install-Module -Name ImportExcel -Scope CurrentUser -Force
get-installedmodule [-name] <shows the version installed>
update-module -name "xyz" <updates the module to the current version>
get-command -module "xyz" <shows all commands in module>

#>
#
'*** Define function for prompt'
#FUNCTION prompt {'{0}> ' -f (split-path $pwd -leaf)}
FUNCTION prompt { write-host "<$(Get-Location)>"
}
#This was to switch between browsers. I have since unistalled chrome beta.
$ThisChrome="Chrome.exe"
#if ($env:COMPUTERNAME -like "VAIOFRED") {$ThisChrome="Chrome.exe"}
#if ($env:COMPUTERNAME -like "SuperComputer") {$ThisChrome="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"}
Function Test-IsWindowsTerminal { [bool]($env:WT_Session)}
function ShowUbuntu {start-process ubuntu1804.exe
}
function DirectorySize {Get-ChildItem -recurse -file | Measure-Object Length -Sum `
    |Select-Object @{name="Num of Files";expression ={"{0:n0}" -f $_.count}}, sum, @{name="GB";expression={[math]::round($_.sum/(1024*1024*1024),6)}}  |format-list *
}
function fCheckForUpdates {start-process ms-settings:windowsupdate;UsoClient.exe StartInteractiveScan ;get-process uso*
}
set-alias CheckForUpdates -value fCheckForUpdates -Option Readonly -force -passthru | format-list

function ms-settings ($arg) {start-process ms-settings:$arg
}
function ShowWindowsComputerInfo {Get-ComputerInfo -property Windows*
}
#Show-ControlPanelItem system
#Profile Stuff
function fCdProfile {push-location (split-path $profile -parent)
}
set-alias -name CdProfile -value fCdProfile -Option Readonly -force -passthru | format-list
function SourceProfile {cdprofile;. .\profile.ps1
} #something is wrong with this.
function fEditProfile {code $profile.currentuserallhosts
}
set-alias -name EditProfile -value fEditProfile -Option Readonly -force -passthru | format-list
function showMessages {invoke-item (join-path $env:HOMEPATH "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Chrome Apps\Messages.lnk")}
function showMaps {invoke-item (join-path $env:HOMEPATH "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Chrome Apps\Google Maps.lnk")}
function showPhotos {invoke-item (join-path $env:HOMEPATH "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Chrome Apps\Google Photos.lnk")}
function SearchProfile ($ThisMatch) {Select-String -path $profile.CurrentUserAllHosts -Pattern $ThisMatch -SimpleMatch}
function showSwimClubExcel {invoke-item $env:OneDrive\swimclub\2019\"SwimRiteNow.xlsm"}
function showSwimClubAccess {invoke-item $env:OneDrive\swimclub\2019\"SwimRiteNowV3.accdb"}
function showSwimClubFTP {push-location $env:OneDrive\"swimclub\2019\Reports";ftp.exe -s:ftp.txt; start-process chrome -argumentlist www.fredjacobowitz.com;Pop-Location}
function showSwimClubCd {Push-Location $env:OneDrive"\SwimClub\2019"}
set-alias -name cdsc -Value showSwimClubCd -Option ReadOnly -Force -PassThru |Format-List

function showSwimClubCdPowershell {if ($env:COMPUTERNAME -eq "VAIOFRED"){push-location $env:OneDrive\Powershell\SwimClub} else {Push-Location $env:OneDrive"\Documents\Powershell\SwimClub"}}
function showSwimClubMakeReports  {
    if ($env:COMPUTERNAME -eq "VAIOFRED"){push-location $env:OneDrive\Powershell\SwimClub}
    else {Push-Location $env:OneDrive"\Documents\Powershell\SwimClub"}
    ./GenerateBestTimesAndRankReports.ps1
    pop-location
}
function showSwimClubPage {start-process $ThisChrome -ArgumentList "www.fredjacobowitz.com\hewlettswimclub"}
function showSwimClubHTMLreport ($file) {start-process chrome -ArgumentList "file://$((get-childitem $file).fullname)"}
#function showFileDateTime {if($IsCoreClr){get-date -UFormat %FT%T}else{get-date -UFormat %Y-%m-%dT%T | ForEach-Object{$_ -replace ":","-"}}}
function showFileDateTime {get-date -Format "yyyy-MM-ddTHH-mm-ss"}
# pwsh - get-date -UFormat %FT%T
# get-date -format "yyyy-MM-ddTHH-mm-ss" #works for all versions of powershell
#function showFileDate {get-date -UFormat %F}
function showFileDate {get-date -Format "yyyy-MM-dd"}
function showRenameFiles($files){foreach ($file in $files){
    $time=showFileDateTime;
    rename-item -Confirm -path $file -NewName $time$($file.name)}
}
function Push-ProfileToRepository {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $Repository = (join-path $env:homepath \Dropbox\Private\Powershell\Profiles\CurrentUser)
    $thisPath = $Profile.CurrentUserAllHosts
    "Repository is {0}:" -f $Repository
    $RepositoryProfile = get-content (join-path $Repository \Profile.ps1) | select-object -first 1
    Write-Warning $RepositoryProfile
    "Working Profile is {0}:" -f $thisPath
    $thisProfile=get-content $thisPath |select-object -first 1
    Write-Warning $thisProfile;write-host ""
    if ($thisProfile -ne $RepositoryProfile) {write-warning "Version numbers are different."} else {write-warning "Version numbers are the same."}
    $temp=compare-object -referenceObject (get-content (join-path $Repository \Profile.ps1))  -DifferenceObject  (get-content $thisPath)
    if ($temp.count -eq 0){write-warning "Files are the same."}
    else {
        write-warning "Files are different in $($temp.count) places."
        $temp|format-list *
        copy-item -confirm -path $thisPath -destination $Repository
        if($? -eq $true){write-warning "Copy Completed"}else{"Copy Failed"}
    }
}
set-alias PushProfileToRepository -value Push-ProfileToRepository -Option Readonly -force -passthru | format-list; #remove-variable thisPath

#The powershell OneDrive directory $env:Onedrive\Documents\Powershell is owned by Fred@Fred.Jacobowitz.com and shared as \Powerhell with FredSwims@Outlook.com
function fGetProfile {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $thisPath = (join-path $env:HomePath\Dropbox\Private\Powershell\Profiles\CurrentUser Profile.ps1)
    $thisDestination = $Profile.CurrentUserAllHosts
    "In Repository is {0}:" -f $thisPath
    write-warning (get-content $thisPath | select-object -first 1)
    "Working Profile is {0}:" -f $thisDestination
    write-warning (get-content $thisDestination|select-object -first 1)
    copy-item -confirm -path $thispath -destination (split-path -parent $profile)
}
set-alias GetProfileFromRepository -value fGetProfile -Option Readonly -force -passthru | format-list; #remove-variable thisPath#
#End Profile Stuff

function fGetDirDays ($days = 0,$file ="*") {get-childitem -file -path $file | where-object {$_.LastWriteTime.Date -ge [datetime]::today.Adddays(-[System.Math]::abs($days))} | sort-object  lastwritetime
} # (get-date).date is equivalent to [datetime]::today
set-alias -name lsl -value fGetDirDays -Option Readonly -force -passthru | format-list

#regionQuicken
<# Decaprecated
"QUICKEN***** function and alias"
#https://ss64.com/ps/call.html explanation of call operator "&"
#even though it looks like we are dot sourcing the file - it doesn't effect the launching namespace because it is calling 'start-process'
function fQuickn ($arg = "home") {
    push-location $env:homepath
    $runThis = join-path (resolve-path dropbox).path -ChildPath \Private\Q\LoadQuickenDb.ps1
    pop-location; "String is {0}" -f $runThis
    start-process powershell -Args "-noprofile -command & {. '$runThis' $arg.qdf -speak }"  #"note how $runThis is in single quotes - Super Computer"
    remove-variable runThis
}
set-alias -name Quickn -value fQuickn -Option Readonly -force -passthru | format-list
DECAPRECATED
#>
#region Quickn Q U I C K E N
"*** Version::2019-05-31.0"
function Show-Quickn ($arg = "home") {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    #$runThis = join-path (resolve-path dropbox).path -ChildPath \Private\Q\LoadQuickenDb1.ps1
    $runThis = join-path -path $home -ChildPath \Dropbox\Private\Q\LoadQuickenDb1.ps1
    if ($arg.tolower() -eq "edit") {
        Read-Host "About to edit '$runThis'; Let's be careful out there!"
        code $runThis
    }
    else {
        $arg += ".qdf" #add extension
        push-location $env:homepath
        pop-location; "String is {0}" -f $runThis
        #This was the way to launch the old script before it was a function with params.
        #Can I do something like this to combat the spaces in 'Super Computer'resolve-path $runthis
        #start-process powershell -Args "-noprofile -command & {. '$runThis' $arg -speak }"  #"note how $runThis is in single quotes - Super Computer"
        start-process pwsh -Args "-noprofile -command & {. '$runThis' $arg -speak }"  #"note how $runThis is in single quotes - Super Computer"
        #This is to launch the script modified to be a function with params.
        #powershell.exe -noprofile -file $runThis  -Filename $arg -Speak
        #Version::2019-06-07.0
        #Current invocation follows. Because 'Super Computer' has an embedded space we still need to muck with single quotes.
        #start-process -RedirectStandardError $env:homepath\fred.out Powershell.exe -Args "-noprofile -command & {. '$runThis'  -Filename $arg -Speak}"
        <#     $command="-command  '$runThis' -Filename $arg -Speak"
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $encodedCommand = [Convert]::ToBase64String($bytes)
        start-process -RedirectStandardError $env:homepath\fred.out powershell.exe -args "-noprofile -encodedCommand $encodedCommand"
        #>    remove-variable runThis
    }
}
set-alias -name ShowQuickn -value Show-Quickn -Option Readonly -force -passthru | format-list
#endregion test
function ShowQuicknLog {start-process notepad2 -args $env:homedrive\$env:homepath\Documents\Quicken\Powershell.out
}
function showSpeedTest {start-process pwsh -Args  "-noprofile -noexit -command & {. '$((join-path $home mystuff speedtest.ps1))'}"}
#end-region Quickn

function Show-BackitUp ($arg = "SwimRiteNowV3.accdb") {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    push-location $env:homepath
    $runThis = join-path (resolve-path dropbox).path -ChildPath \Private\Q\LoadQuickenDb1.ps1
    $runthis=join-path $env:homepath\MyStuff -childpath BackItUp.ps1
    pop-location; "String is {0}" -f $runThis
    #This was the way to launch the old script before it was a function with params.
    #Can I do something like this to combat the spaces in 'Super Computer'resolve-path $runthis
    start-process powershell -Args "-noprofile -command & {. '$runThis' $arg -speak }"  #"note how $runThis is in single quotes - Super Computer"
    #This is to launch the script modified to be a function with params.
    #powershell.exe -noprofile -file $runThis  -Filename $arg -Speak
    #Version::2019-06-07.0
    #Current invocation follows. Because 'Super Computer' has an embedded space we still need to muck with single quotes.
    #start-process -RedirectStandardError $env:homepath\fred.out Powershell.exe -Args "-noprofile -command & {. '$runThis'  -Filename $arg -Speak}"
    <#     $command="-command  '$runThis' -Filename $arg -Speak"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    start-process -RedirectStandardError $env:homepath\fred.out powershell.exe -args "-noprofile -encodedCommand $encodedCommand"
    #>    remove-variable runThis
}
set-alias -name ShowBackItUp -value Show-BackitUp -Option Readonly -force -passthru | format-list



function ShowAutoStartDir {push-location (join-path $env:homepath "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup");get-item *}
function cdTax {push-location (join-path $env:homepath "Dropbox/Private/Tax/")}

function ShowMyIp {start-process $ThisChrome -ArgumentList www.whatismyipaddress.com}

function showKeep {start-process -filepath $ThisChrome -ArgumentList "https://keep.google.com/u/0/"
}
function ShowGmail {Start-Process -filepath $ThisChrome -argumentlist www.gmail.com}
function ShowFacebook {Start-Process -filepath $ThisChrome -argumentlist www.facebook.com}
#
function showContacts{start-process $ThisChrome -ArgumentList "https://contacts.google.com/?hl=en&tab=mC"}
function showCalendar{start-process $ThisChrome -ArgumentList "https://www.google.com/calendar?tab=wc"}
function showssh {ssh fredjacobowitz@fredjacobowitz.com}
function showPlc {push-location "C:\Users\Super Computer\dropbox\Private\CPT2\PLCSnowCompany";invoke-item "*.pdf"
}
#https://peter.sh/experiments/chromium-command-line-switches/#load-extension
'Alias ReadGmail'
function ShowGmailIncognito {Start-Process -filepath $ThisChrome -argumentlist "--incognito www.gmail.com"
}
#
# Windows Event Log
'Alias EventShutdown'
#function fEventShutdown {get-eventlog -logname system |? {$_.eventid -in 41,1074,6006,6008} }
    function fEventShutdown ($arg = 0) {get-winevent -LogName system | where-object {$_.id -in 1, 41, 42, 107, 1074, 6006, 6008 -and $_.timecreated -ge [datetime]::today.Adddays(-$arg)} |select-object timecreated, id, InstanceId, message | sort-object -property timecreated |format-list *;get-date}
    set-alias -name ShowShutdownEvent -value fEventShutdown -Option Readonly -force -passthru | format-list
#
Function ShowEventLog2 {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    #this is what happens when you don't document something
    #I think this InstanceId are tasks automatically started.
    Get-EventLog -LogName System -InstanceId 1073748869 |
    ForEach-Object {
        [PSCustomObject]@{
        Date = $_.TimeGenerated
        Name = $_.ReplacementStrings[0]
        Path = $_.ReplacementStrings[1]
        StartMode = $_.ReplacementStrings[3]
        User = $_.ReplacementStrings[4]
    }
}  | Out-GridView
}
function fSayIt ($arg=2){$file=(join-path $home\MyStuff speakclipboard.ps1);
    start-process powershell.exe -ArgumentList " -WindowStyle hidden -nologo -noprofile -command  & {. '$file' $arg}"}
function ffSayIt {start-process powershell -Argument "-nologo -noprofile & {push-location '$Env:Homepath\PowershellScripts.lnk\MyStuff'; .\speakclip.ps1 -filename 'ellen.txt' -speak }"}
# I cannot reference the path as $env:homepath\MyStuff\SpeakClip.ps1 on SuperComputer because of the embedded space in 'Super Computer'
# But what I can do is 'set-location' to the directory and then reference the 'ps1' file.
# MyStuff is a symbolic link.
# See https://social.technet.microsoft.com/Forums/scriptcenter/en-US/88903837-b9f2-41ea-986c-b66ce8854587/powershell-startprocess-how-to-start-a-powershell-script-with-arguments?forum=ITCG

#set-alias -name SayIt -value fSayIt -Option Readonly -force -passthru | format-list

#function ShowExplorerHere {start-process explorer -ArgumentList (get-location)
    #}
function ShowExplorerHere {invoke-item .}

function ElevateMe {if($PSVersionTable.psedition -eq "Desktop"){Start-process Powershell -Verb runas}else{start-process Pwsh -Verb runas}
}
function ShowScanner {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $scan="C:\Program Files (x86)\Canon\MP Navigator EX 2.0\mpnex20.exe"
    start-process $scan;Start-Sleep -seconds 1
    if (get-process mpnex20){"Patience is a virtue."}else{"Oops!"}
    #explorer 'C:\Users\Super Computer\Pictures\MP Navigator EX\'
    start-process explorer -ArgumentList 'C:\Users\Super Computer\Pictures\MP Navigator EX\'
}
function Search-Google {
    Begin {
        Write-Host "In function $($MyInvocation.MyCommand.Name): "
        $query = 'https://www.google.com/search?q='
    }
    Process {
        if ($args.Count -eq 0) {
            "Args were empty, commiting `$input to `$args"
            Set-Variable -Name args -Value (@($input) | ForEach-Object { $_ })
            "Args now equals $args"
            $args = $args.Split()
        }
        else {
            "Args had value, using them instead"
        }
        <#
        Write-Host $args.Count, "Arguments detected"
        "Parsing out Arguments: $args"
        for ($i = 0; $i -le $args.Count; $i++) {
            $args | ForEach-Object { "Arg $i `t $_ `t Length `t" + $_.Length, " characters" }
        }
        $args | ForEach-Object { $query = $query + "$_+" }
        #>
    }
    End {
        <#
        $url = $query.Substring(0, $query.Length - 1)
        "Final Search will be $url `nInvoking..."
        Start-Process "$url"
        #>
        $search = $args
        ($url=$query + $search) #display on console
        Start-Process $url
    }
}#END Search-Google
set-alias -name ShowGoogle -value Search-Google  -option readonly -force -passthru | format-list


function Start-TurboTax {start-process explorer "C:\Program Files (x86)\TurboTax\Home & Business 2018\32bit\turbotax.exe"
}
set-alias -name ttax -value Start-TurboTax  -option readonly -force -passthru | format-list
function cdttax {set-location $env:homepath\Dropbox\Private\Tax\TurboTax
}
# Get Last Command - copies the last n commands to the clipboard
Function CopyHistoryCommands($Number) {
  Write-Warning "In function $($MyInvocation.MyCommand.Name): "
  $CommandLength = (Get-History | Measure-Object).Count
  $Start = $CommandLength - $Number + 1
  [array]$CommandRange = @()
  Foreach ($obj in ($Start..$CommandLength)) { $CommandRange+=$obj; $obj++ }
  #Foreach ($obj in ($Start .. $CommandLength)) {$CommandRange += $obj}
  (Get-History $CommandRange).CommandLine | Clip
  Write-Host -NoNewline "Last ";Write-Host -NoNewLine -ForegroundColor Green "$($Number) ";Write-Host "commands have been copied to the clipboard."
}

#copy by id to clipboard
function CopyHistoryById {
    param ( [int]$Id = (Get-History -Count 1).Id )
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $history = Get-History -Id $Id -ErrorAction SilentlyContinue -ErrorVariable getHistoryError
    if ($getHistoryError)
    {
        Write-Warning "$($MyInvocation.MyCommand.Name): $($getHistoryError.Exception.Message)"
    } # if ($getHistoryError) ...
    else {
        $history.CommandLine | clip.exe
    } # if ($getHistoryError) ... else
}
#New-Alias -Force -ErrorAction SilentlyContinue chy Copy-History;

function Show-Desktop {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $x = New-Object -ComObject Shell.Application
    $x.ToggleDesktop()
    $x=$null
}
set-alias showDesktop -value Show-Desktop -Option Readonly -force -passthru | format-list
#"Version::2019-05-14.0"
function showkeepass {start-process "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\KeePass 2.lnk"
}
function ShowMedicalHistory {invoke-item (join-path $env:HOMEPATH\dropbox\private\MedicalSpecial "Medical Conditions.docx")
}
function ShowMedicalFolder {invoke-item "$env:HOMEPATH\Google Drive\Medical"
}
set-alias ShowWindowsTerminal -value wt.exe -Option Readonly -force -passthru | format-list

function ShowWhereIs ($arg) {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $dir=$env:Path
    $dir=$dir.split(";") | Sort-Object
    foreach ($path in $dir){write-host $path}
    Write-host "******"
    #$fullpath=$dir | ForEach-Object {Get-ChildItem $_/$arg}
    $dir  | `
    ForEach-Object {Get-ChildItem -path $_/$arg -File -Force -ErrorAction SilentlyContinue} |sort-object -property $_.directoryname -unique | `
    ForEach-Object `
        -process {
            [pscustomobject]@{
            Name=$_.name
            Path=$_.DirectoryName
            LastWriteTime=$_.lastwritetime
            }
    }
}
function ShowWhere ($arg) {
    $paths=where.exe $arg
    If ($lastExitCode -eq 0) {foreach($path in $paths) {[pscustomobject]@{Name=$arg;Path=split-path -parent $Path}}} else {}
}
# Harriet
function cdHarriet {Push-Location $env:homepath"\Dropbox\Private\HarrietTrust";get-childitem -Directory|Select-Object Name}
#
'Add Type accelerators'
#define type accelerator for type accelerators #https://blogs.technet.microsoft.com/heyscriptingguy/2013/07/08/use-powershell-to-find-powershell-type-accelerators/
$xlr = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$xlr::Add('accelerators', $xlr)
"Try this '[accelerators]::get'"
"ShowWindowsComputerInfo"
"EOF"
#(new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1") | iex
#Don't use PSReadLine with Powershell ISE
#If(System.Management.Automation.Internal.Host.InternalHost.Name -eq 'ConsoleHost') {import-module -versbose PSReadline}
#If($Host.Name -eq 'ConsoleHost') {import-module -verbose PSReadline}
Write-Host "Try Windows Admin Center localhost:6516"
write-host "https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/overview#introduction"
#notes

"Profile specific code ends here"
write-warning "End of $Temp";Remove-Variable "ProfileNames";  Remove-Variable "Count";Remove-Variable Temp
