"*** Version::2021-02-21"
<#
    Quicken
    ShowMedicalFolder now points to "Google Drive"
    Function ShowMyGroups
    Function ShowConnections
    find-module psreadline -AllowPrerelease|Install-Module
    find-module microsoft.powershell.crescendo -allowprerelease
    Refactor Function Show-Quicken - some new things learned.
    start-process (join-path $env:ProgramData "\Microsoft\Windows\Start Menu\Programs\Mozilla VPN.lnk")
    Refactor GetProfileFromRepository
    Moved four profile related routines towards top
    AreProfileInSync now ShowAreProfileInSync
    GetProfileFromDirectory
    Function AreProfilesInSync
    ShowTestAdministrator Running As Administrator?
    show psreadline version
    out-consolegridview
    working on function defineit.
    incorporate get-WindowsUpdate and Install-WindowsUpdate
    function SearchProfile
    function showdeletetempfiles added before stats
    function cdharriet new location
    function fShowFormattedSubDirectorySize
    function fShowSubDirectorySize
    Tweak showdeletetempfiles
    My functions look like fjFunctionName
    Usage of $env:APPDATA to reference paths to windows apps to invoke-item. FJ
    "*** Version::2020-07-30.2"
    add fGetDirectorySize showdeletetempfiles
    fGetProfile mods
    ShowDeleteTempFiles
    mods to showDirectorySize
    fEditWT
    Self Aliased Functions in PowerShell
    NoExit on showQuicken
    Remove Set-PSReadLine -- InsertPairedBraces
    ShowGetProcess with minutes and seconds
    ShowSpeedTest;fjsayit
    Identify this profile
    $ProfileNames ="AllUsersAllHosts", "AllUsersCurrentHost", "CurrentUserAllHosts", "CurrentUserCurrentHost"
#>
$ProfileNames = ($profile | Get-Member -membertype noteproperty).name
$count = 0
($ProfileNames).foreach( { if ($PSCommandPath -eq $($Profile.$_)) { $Temp = "profile [{0}] with path {1}" -f $_, $PSCommandPath ; $Count++ } })
write-warning "Start of $($Temp)"
If ($count -ne 1) { write-host -foregroundColor 'red' "Which profile is this?" }
if ([Environment]::Is64BitOperatingSystem) { "*** Is 64 bit OS" } else { "*** Is 32 bit OS" }
if ([Environment]::Is64BitProcess) { "*** Is 64 bit process" } else { "*** Is 32 bit process" }
if ($IsCoreClr) { "Running Pwsh" } else { "Running Powershell" }
if ($env:WT_SESSION) { "Running in Windows Terminal" }
"Profile specific code starts here"

#region Profile Stuff - Four functions
function GetMySID {
    # https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
    $target="{0}\{1}" -f $env:userdomain, $env:username
    $sid=Get-LocalGroupMember -group "homeusers" |Where-Object name -eq $target |select-object sid
    return $sid
}
function GetMyGroups {
    $sid=GetMySID
    foreach ($name in get-localGroup) `
    {
        Get-LocalGroupMember -group $name `
        | where-object SID -eq ($sid).sid.value `
        | select-object @{ Name = 'Group'; Expression = { $name } }, name, sid, "principalsource", objectClass
    }
}
function ShowMyIp { start-process $ThisChrome -ArgumentList www.whatismyipaddress.com }

#beginregion Four Profile Functions Follow
#The powershell OneDrive directory $env:Onedrive\Documents\Powershell is owned by Fred@Fred.Jacobowitz.com and shared as \Powerhell with FredSwims@Outlook.com
function fjEditProfile {
    [Alias('EditProfile')] param ([switch]$repository)
    if ($repository) {
        $ThisProfile = (join-path (join-path $env:home \Dropbox\Private\Powershell\Profiles\CurrentUser) "profile.ps1")
        read-host "Editing Profile in Repository - $($ThisProfile)"
    }
    else { $ThisProfile = $profile.currentuserallhosts }
    code $ThisProfile
}
function fjGetProfile {
    [cmdletbinding()]
    [Alias('GetProfileFromRepository')]
    Param()
    Write-Warning "In function $($MyInvocation.MyCommand.Name):r2020-11-13.1"
    $lines = 2
    $RepoProfile = (join-path $env:Dropbox "Private\Powershell\Profiles\CurrentUser\Profile.ps1")
    $localProfile = $Profile.CurrentUserAllHosts
    "Repository Profile is {0}:" -f $RepoProfile
    (get-content $RepoProfile | select-object -first $lines) | write-warning; write-host "<->"
    "Working Profile is {0}:" -f $localProfile
    (get-content $localProfile | select-object -first $lines) | write-warning
    if ((Get-FileHash $profile.CurrentUserAllHosts).Hash -eq `
        (Get-FileHash $RepoProfile).Hash) {write-host "File hashes are the same."}
    else {
        [console]::beep(1500,200)
        Write-Error "File hashes are different."
        copy-item -confirm -path $RepoProfile -destination $localProfile
    }

    #if($?){write-warning "Souncing"; &(. $profile.CurrentUserAllHosts)}
}
# set-alias GetProfileFromRepository -value fGetProfile -Option Readonly -force -passthru | format-list; #remove-variable thisProfile#
function Push-ProfileToRepository {
    [cmdletbinding()]
    [Alias('PushProfileToRepository')]
    Param()
    Write-Warning "In function $($MyInvocation.MyCommand.Name):r2020-11-13 "
    $Repository = (join-path $env:Dropbox "\Private\Powershell\Profiles\CurrentUser")
    $thisProfile = $Profile.CurrentUserAllHosts
    "Repository is {0}:" -f $Repository
    $RepositoryVersion = get-content (join-path $Repository "Profile.ps1") | select-object -first 2
    # Write-Warning $RepositoryProfile
    $RepositoryVersion | write-warning; write-host "<->"
    "Working Profile is {0}:" -f $thisProfile
    $thisProfileVersion = get-content $thisProfile | select-object -first 2
    # Write-Warning $thisProfile
    $thisProfileVersion | Write-Warning; write-host ""
    # if ($thisProfileVersion -ne $RepositoryProfileVersion) { write-warning "Version numbers are different." } else { write-warning "Version numbers are the same." }
    $temp = compare-object -referenceObject ( get-content ( join-path $Repository "Profile.ps1" ) )  -DifferenceObject  (get-content $thisProfile)
    if ($temp.count -eq 0) { write-warning "Files are the same." }
    else {
        write-warning "Files are different in $($temp.count) places."
        $temp | format-list *
        copy-item -confirm -path $thisProfile -destination $Repository
        if ($? -eq $true) {}else { "Copy Failed" }
    }
}
# set-alias PushProfileToRepository -value Push-ProfileToRepository -Option Readonly -force -passthru | format-list; #remove-variable thisProfile
function ShowAreProfilesInSync {
    Write-Warning "In function $($MyInvocation.MyCommand.Name):r2020-11-13.3"
    $localProfile=$profile.CurrentUserAllHosts
    $getItem=get-item $localProfile
    if ($getItem.LinkType -eq "SymbolicLink" ) {$localProfile=$getItem.Target}
    $repoProfile=(join-path $env:Dropbox "Private\Powershell\Profiles\CurrentUser\Profile.ps1")
    write-host "`tLOCAL PROFILE: last update $((get-item $localProfile).LastWriteTime) "
    (get-content $localProfile | select-object -first 2) | write-host
    write-host "`tREPO  PROFILE: last update $((get-item $repoProfile).LastWriteTime) "
    (get-content $repoProfile | select-object -first 2) | write-host
    ((Get-FileHash $localProfile).Hash -eq `
        (Get-FileHash $repoProfile).Hash
    )
}
if (ShowAreProfilesInSync) {"Profiles are in Sync"} else {[console]::beep(1500,200);read-host "Profiles are not in Sync"}
#endregion Profile Stuff

<#
    QUICKEN STUFF
    "C:\ProgramData\Quicken\config\QUICKEN.INI"
 #>

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
get-executionPolicy -list | Format-Table
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

INSTALL-MODULE STUFF
Install-Module -Name ImportExcel -Scope CurrentUser -Force
https://devblogs.microsoft.com/powershell/introducing-consoleguitools-preview/
Install-Module Microsoft.PowerShell.ConsoleGuiTools #for out-consolegridview

install-Module microsoft.powershell.graphicaltools #for out-gridview
get-installedmodule [-name] <shows the version installed>
update-module -name "xyz" <updates the module to the current version>
get-command -module "xyz" <shows all commands in module>
show-command xxxx
help get-command -ShowWindow

#>
#
'*** Define function for prompt'
#FUNCTION prompt {'{0}> ' -f (split-path $pwd -leaf)}
#FUNCTION prompt { write-host "<$(Get-Location)>✔🐱‍🚀"   }
#https://www.hanselman.com/blog/HowToMakeAPrettyPromptInWindowsTerminalWithPowerlineNerdFontsCascadiaCodeWSLAndOhmyposh.aspx
Import-Module posh-git
Import-Module oh-my-posh
Set-Theme Paradox

# PSReadLine STUFF
#https://github.com/PowerShell/PSReadLine/blob/master/PSReadLine/SamplePSReadLineProfile.ps1
#get-PSRepository
<#
Name                      InstallationPolicy   SourceLocation
----                      ------------------   --------------
PSGallery                 Trusted              https://www.powershellgallery.com/api/v2
#>
#find-module psreadline -AllowPrerelease|Install-Module
Set-PSReadLineOption -PredictionSource History

<#
Locate this function in the url above.
Set-PSReadLineKeyHandler -Key '(','{','[' `
                         -BriefDescription InsertPairedBraces `
                         -LongDescription "Insert matching braces" `
                         -ScriptBlock {
#>
# Sometimes you enter a command but realize you forgot to do something else first.
# This binding will let you save that command in the history so you can recall it,
# but it doesn't actually execute.  It also clears the line with RevertLine so the
# undo stack is reset - though redo will still reconstruct the command line.
Set-PSReadLineKeyHandler -Key Alt+w `
    -BriefDescription SaveInHistory `
    -LongDescription "Save current line in history but do not execute" `
    -ScriptBlock {
    param($key, $arg)

    $line = $null
    $cursor = $null
    [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
    [Microsoft.PowerShell.PSConsoleReadLine]::AddToHistory($line)
    [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
}
#This was to switch between browsers. I have since unistalled chrome beta.
$ThisChrome = "Chrome.exe"
#if ($env:COMPUTERNAME -like "VAIOFRED") {$ThisChrome="Chrome.exe"}
#if ($env:COMPUTERNAME -like "SuperComputer") {$ThisChrome="C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"}
Function Test-IsWindowsTerminal { [bool]($env:WT_Session) }
function ShowUbuntu {
    start-process ubuntu1804.exe
}
function fShowSubDirectorySize {
    [Alias('ShowSubDirectorySize')] param ([string[]]$Path = "*")
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    write-warning "$($path)"
    $colItems = get-childitem -Directory  -Path $path
    foreach ($i in $colItems) {
        $subFolderItems = Get-ChildItem $i.FullName -recurse -force | Where-Object { $_.PSIsContainer -eq $false } | Measure-Object -property Length -sum | Select-Object Sum
        $thisobject = [pscustomobject]@{
            Size = $subFolderItems.Sum
            Name = $i.FullName
        }
        $thisobject
    }
}
function fShowFormattedSubDirectorySize{[Alias('ShowFormattedSubDirectorySize')] param ([string[]]$Path="*")
fShowSubDirectorySize -path $path | sort-object -property size -Descending|Select-Object @{name="Bytes";exp={"{0,16:n0}" -f $psitem.size}}, name
}
<#
function DirectorySize {[Alias('ShowDirectorySize')] param ()
    Get-ChildItem -recurse -file | Measure-Object Length -Sum |`
    Select-Object @{name = "Num of Files"; expression = { "{0:n0}" -f $_.count } },
     @{name = "Bytes"; expression = { "{0:n0}" -f $_.sum } },
     @{name = "GB"; expression = { [math]::round($_.sum / (1Gb), 6) } }  | format-list *
}
#>
function DirectorySize {[Alias('ShowDirectorySize')] param ([string[]]$Path="*",[switch]$r)
    $HashArgs = @{
        Path=$Path
        Recurse=$r
    }
    Get-ChildItem @HashArgs | Measure-Object -Property "Length" -Sum |`
    Select-Object @{name = "Num of Files"; expression = { "{0:n0}" -f $_.count } },
     @{name = "Bytes"; expression = { "{0:n0}" -f $_.sum } },
     @{name = "GB"; expression = { [math]::round($_.sum / (1Gb), 6) } }  | format-list *
}
function fjDeleteTempFiles {[Alias('ShowDeleteTempFiles')] param ([string[]]$Path="*",[switch]$w)
    $path=@("*.ico","*.exe","*tmp*","*.log","*.ses","*.shd","Teamviewer","*.msi","PSES*","_ME*","*.mtx","*.png","????????-????-????-????-????????????","remote*")
    $HashArgs = @{
        Path=$path
        Whatif=$w
        Verbose=$true
        Force=$true
    }
    push-location $env:TEMP
    get-item *
    ($temp=ShowDirectorySize -r) ; Read-Host "Enter to continue"
    remove-item @HashArgs
    get-item *
    ShowDirectorySize -r
    "Before"
    $temp
    Pop-Location
}

function fCheckForUpdates {
    [Alias('CheckForUpdates')] param ([switch]$new)
    if (!$new) {
        start-process ms-settings:windowsupdate; UsoClient.exe StartInteractiveScan ; get-process uso*
    }
    else {
        # ElevateMe
        Get-WindowsUpdate -Verbose
        Read-Host "pause"
        Install-WindowsUpdate -AcceptAll -Verbose
    }
}
#set-alias CheckForUpdates -value fCheckForUpdates -Option Readonly -force -passthru | format-list

# https://ss64.com/nt/syntax-settings.html
# works for ALL versions of Powershell
# Start-Process "ms-settings:appsfeatures"
# kill process using
# get-process systemSettings|stop-process systemSettings
function ms-settings ($arg) {
    start-process ms-settings:$arg
}
function ShowWindowsComputerInfo {
    Get-ComputerInfo -property Windows*
}
#This only works with Windows Powershell
#list item -> #Get-ControlPanelItems *
#Show-ControlPanelItem -name system
#Show-ControlPanelItem -CanonicalName microsoft.system
#Show-ControlPanelItem "programs and features"
#Show-ControlPanelItem -CanonicalName "ProgramsAndFeatures"

#Profile Stuff
function fjCdProfile {
    [Alias('CdProfile')] param () push-location (split-path $profile -parent)
}
#set-alias -name CdProfile -value fCdProfile -Option Readonly -force -passthru | format-list
function SourceProfile {
    cdprofile; . .\profile.ps1
} #something is wrong with this.

function fjEditWT {
    [cmdletbinding()]
    [Alias('EditWT')] param ($p)
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    if ($p -eq "p") { code (join-path $env:LOCALAPPDATA "Packages\Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe\LocalState\settings.json") }
    else { code (join-path $env:LOCALAPPDATA "Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json") }
}
# set-alias -name EditProfile -value fEditProfile -Option Readonly -force -passthru | format-list
function showgDrive { start-process $ThisChrome -ArgumentList "https://drive.google.com/drive/my-drive" }
function showGMessages { invoke-item (join-path $env:APPDATA "\Microsoft\Windows\Start Menu\Programs\Chrome Apps\Messages.lnk") }
function showGMaps { invoke-item (join-path $env:APPDATA "\Microsoft\Windows\Start Menu\Programs\Chrome Apps\Google Maps.lnk") }
function showGPhotos { invoke-item (join-path $env:APPDATA "\Microsoft\Windows\Start Menu\Programs\Chrome Apps\Google Photos.lnk") }
function showGDuo { invoke-item (join-path $env:APPDATA "\Microsoft\Windows\Start Menu\Programs\Chrome Apps\Google Duo.lnk") }
function getDirectories {
    [cmdletbinding()]
    [Alias('ld')] param ($path=$null)
    get-childitem -Directory -path $path
}
function get-lastwritetime {
    [cmdletbinding()]
    [Alias('lwt')] param ($path=$null)
    get-childitem  -path $path |Sort-Object -property LastWriteTime
}

function SearchProfile ($ThisMatch, $context=0) { Select-String -path $profile.CurrentUserAllHosts -Pattern $ThisMatch -SimpleMatch -Context $context}
function showSwimClubExcel { invoke-item $env:OneDrive\swimclub\2019\"SwimRiteNow.xlsm" }
function showSwimClubAccess { invoke-item $env:OneDrive\swimclub\2019\"SwimRiteNowV3.accdb" }
function showSwimClubFTP { push-location $env:OneDrive\"swimclub\2019\Reports"; ftp.exe -s:ftp.txt; start-process chrome -argumentlist www.fredjacobowitz.com; Pop-Location }
function showSwimClubCd { Push-Location $env:OneDrive"\SwimClub\2019" }
set-alias -name cdsc -Value showSwimClubCd -Option ReadOnly -Force #-PassThru | Format-List

function showSwimClubCdPowershell { if ($env:COMPUTERNAME -eq "VAIOFRED") { push-location $env:OneDrive\Powershell\SwimClub } else { Push-Location $env:OneDrive"\Documents\Powershell\SwimClub" } }
function showSwimClubMakeReports {
    if ($env:COMPUTERNAME -eq "VAIOFRED") { push-location $env:OneDrive\Powershell\SwimClub }
    else { Push-Location $env:OneDrive"\Documents\Powershell\SwimClub" }
    ./GenerateBestTimesAndRankReports.ps1
    pop-location
}
function showSwimClubPage { start-process $ThisChrome -ArgumentList "www.fredjacobowitz.com\hewlettswimclub" }
function showSwimClubHTMLreport ($file) { start-process chrome -ArgumentList "file://$((get-childitem $file).fullname)" }
#function showFileDateTime {if($IsCoreClr){get-date -UFormat %FT%T}else{get-date -UFormat %Y-%m-%dT%T | ForEach-Object{$_ -replace ":","-"}}}
function showFileDateTime { get-date -Format "yyyy-MM-ddTHH-mm-ss" }
# pwsh - get-date -UFormat %FT%T
# get-date -format "yyyy-MM-ddTHH-mm-ss" #works for all versions of powershell
#function showFileDate {get-date -UFormat %F}
function showFileDate { get-date -Format "yyyy-MM-dd" }
<#
function showRenameFiles($files){foreach ($file in $files){
    $time=showFileDateTime;
    rename-item -Confirm -path $file -NewName $time$($file.name)}
}
function showNewRenameFiles([System.IO.FileInfo[]]$files){
    #arg1 is fileobject
    $time=showFileDateTime;
    #Use a delay-bind script-block
    $files|rename-item -Confirm `
      -NewName { $time + "-"+ $psitem.Name}
}
#>
function fjshowRenameFiles {
    [Alias('showRenameFiles')]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.IO.FileInfo[]]
        $Files)
    $time = showFileDateTime;
    #Use a delay-bind script-block
    $files | rename-item -Confirm -NewName { $time + "-" + $psitem.Name }
}
function fjGetDirDays {
    [Alias('lsl')]
    param($days = 0, $file = "*")
    get-childitem -file -path $file | where-object { $_.LastWriteTime.Date -ge [datetime]::today.Adddays( - [System.Math]::abs($days)) } | sort-object  lastwritetime
} # (get-date).date is equivalent to [datetime]::today
# set-alias -name lsl -value fGetDirDays -Option Readonly -force -passthru | format-list


function fjGetDirDaysRecurse {
    [Alias('lslr')]
    param($days = 0, $file = "*")
    get-childitem -ErrorAction SilentlyContinue -recurse -file -path $file |`
     where-object { $_.LastAccessTime.Date -ge [datetime]::today.Adddays( - [System.Math]::abs($days)) } | sort-object  lastaccesstime | select-object LastaccessTime, FullName
} # (get-date).date is equivalent to [datetime]::today
# set-alias -name lsl -value fGetDirDays -Option Readonly -force -passthru | format-list

#region Quickn Q U I C K E N
"*** Version::2021-02-21"
function Show-Quicken {
    [cmdletbinding()]
    [Alias('ShowQuicken')]
    param (
        $arg = "home",

        [ValidateSet('C:\Program Files\PowerShell\7-preview\pwsh.exe', 'C:\Program Files\PowerShell\7\pwsh.exe', 'C:\WINDOWS\System32\WindowsPowerShell\v1.0\Powershell.exe')]
        $ThisPowershell="C:\Program Files\PowerShell\7-preview\pwsh.exe",
        
        [switch]$noexit
    )

    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    if ($arg -eq 's') { $arg = "Harriet" }
    $runThis = join-path -path $home -ChildPath \Dropbox\Private\Q\LoadQuickenDb1.ps1
    if ($arg.tolower() -eq "edit") {
        Read-Host "About to edit '$runThis'; Let's be careful out there!"
        code $runThis
    }
    else {
        $arg += ".qdf" #add extension
        "String is {0}" -f $runThis
        # https://ss64.com/ps/call.html
        if ($noexit) { $noexits = "-noexit" } else { $noexits = "" }
        # Call operator is used to evaluate expression in SCRIPT block.
        # Escaped quotes (`"string`") because arguments in script block are strings after evaluation.
        $parameters=@{
            Filepath="$ThisPowershell"
            Args="$($noexits) -noprofile -command & {. '$runThis' $arg -speak}"
        }
        start-process @parameters

<#         start-process `
         -Filepath pwsh `
         -Args "$($noexits) -noprofile -command & {. '$runThis' $arg -speak}"
 #>
         remove-variable runThis

        #This is to launch the script modified to be a function with params.
        #powershell.exe -noprofile -file $runThis  -Filename $arg -Speak
        #Version::2019-06-07.0
        #Current invocation follows. Because 'Super Computer' has an embedded space we still need to muck with single quotes.
        #start-process -RedirectStandardError $env:home\fred.out Powershell.exe -Args "-noprofile -command & {. '$runThis'  -Filename $arg -Speak}"
        <#
        $command="-command  '$runThis' -Filename $arg -Speak"
        $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
        $encodedCommand = [Convert]::ToBase64String($bytes)
        start-process -RedirectStandardError $env:home\fred.out powershell.exe -args "-noprofile -encodedCommand $encodedCommand"
        #>
    }
}
#set-alias -name ShowQuicken -value Show-Quicken -Option Readonly -force -passthru | format-list
#endregion test
function ShowQuicknLog {
    start-process notepad2 -args $env:HOME\Documents\Quicken\Powershell.out
}
function EnableDisableCamera {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Status', 'Enable', 'Disable')]
        [string]$Action
    )
    $thisScript=join-path -path $env:onedrive\PowershellScripts\MyStuff -childpath EnableDisableCamera.ps1
    start-process `
    -Verb "Runas" -Filepath "pwsh" `
    -ArgumentList "-noprofile -noexit -command & {. '$thisScript' -type $Action}"
    Remove-Variable thisScript
}
function showSpeedTest { start-process pwsh -Args  "-noprofile -noexit -command & {. '$((join-path $env:OneDrive\PowershellScripts\MyStuff speedtest.ps1))'}" }
#end-region Quickn
function cdMystuff { Push-Location $env:OneDrive/PowershellScripts/Mystuff }
function GetMyConnections{.(join-path $env:OneDrive/PowershellScripts/Mystuff WhoIsCommunicating.ps1)}

function Show-BackitUp ($arg = "SwimRiteNowV3.accdb") {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    push-location $env:home
    $runThis = join-path (resolve-path dropbox).path -ChildPath \Private\Q\LoadQuickenDb1.ps1
    $runthis = join-path $env:home\MyStuff -childpath BackItUp.ps1
    pop-location; "String is {0}" -f $runThis
    #This was the way to launch the old script before it was a function with params.
    #Can I do something like this to combat the spaces in 'Super Computer'resolve-path $runthis
    start-process powershell -Args " -noprofile -command & {. '$runThis' $arg -speak }"  #"note how $runThis is in single quotes - Super Computer"
    #This is to launch the script modified to be a function with params.
    #powershell.exe -noprofile -file $runThis  -Filename $arg -Speak
    #Version::2019-06-07.0
    #Current invocation follows. Because 'Super Computer' has an embedded space we still need to muck with single quotes.
    #start-process -RedirectStandardError $env:home\fred.out Powershell.exe -Args "-noprofile -command & {. '$runThis'  -Filename $arg -Speak}"
    <#     $command="-command  '$runThis' -Filename $arg -Speak"
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $encodedCommand = [Convert]::ToBase64String($bytes)
    start-process -RedirectStandardError $home\fred.out powershell.exe -args "-noprofile -encodedCommand $encodedCommand"
    #>    remove-variable runThis
}
set-alias -name ShowBackItUp -value Show-BackitUp -Option Readonly -force #-passthru | format-list



function ShowAutoStartDir { push-location (join-path $home "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"); get-item * }
function cdTax { push-location (join-path $home "Dropbox/Private/Tax/") }
function cdPsScripts { Push-Location (join-path $env:OneDrive "Powershellscripts") }
function ShowFacebook { Start-Process -filepath $ThisChrome -argumentlist www.facebook.com }
function showgKeep {
    start-process -filepath $ThisChrome -ArgumentList "https://keep.google.com/u/0/"
}
function ShowGmail { Start-Process -filepath $ThisChrome -argumentlist www.gmail.com }
function showgContacts { start-process $ThisChrome -ArgumentList "https://contacts.google.com/?hl=en&tab=mC" }
function showgCalendar { start-process $ThisChrome -ArgumentList "https://www.google.com/calendar?tab=wc" }
function showssh { ssh fredjacobowitz@fredjacobowitz.com }
function showWsl { wsl -l -v }
function showPlc {
    push-location "C:\Users\Super Computer\dropbox\Private\CPT2\PLCSnowCompany"; invoke-item "*.pdf"
}
function showGps ($num = 20, $name = "*") {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $timex = get-date
    $items = get-process $name |`
        Sort-Object -property StartTime -Descending |`
        Select-Object -WarningAction SilentlyContinue -ErrorAction SilentlyContinue -first $num -Property Starttime, Name, Path
    write-host -ForegroundColor Red "------------"
    $i = 0
    foreach ($item in $items) {
        $i++
        if ($null -eq $item.path ) { $tpath = $item.path } else { $tpath = (Split-Path -Leaf -path $item.path) }
        if ($null -eq $item.StartTime) { $span = New-TimeSpan -start (get-date) -end (get-date) }
        else { $span = new-timespan -start $item.startTime -end $timex }
        # "{0,3} [{1,-20}] <{4:d2}:{5:d2}> {2,-22} -> {3}" -f $i, $item.StartTime, $item.Name, $tpath,$span.minutes,$span.seconds
        "{0,3} [{1,-20}] <{6:mm}m {6:ss}.{6:fff}s> {2,-22} -> {3}" -f $i, $item.StartTime, $item.Name, $tpath, $span.minutes, $span.seconds, $span
    }
}
#https://peter.sh/experiments/chromium-command-line-switches/#load-extension
'Alias ReadGmail'
function ShowGmailIncognito {
    Start-Process -filepath $ThisChrome -argumentlist "--incognito www.gmail.com"
}
#
# Windows Event Log
'Alias EventShutdown'
#function fEventShutdown {get-eventlog -logname system |? {$_.eventid -in 41,1074,6006,6008} }
function fjEventShutdown {[Alias('ShowShutdownEvent')] param ($arg = 0)  get-winevent -LogName system | where-object { $_.id -in 1, 41, 42, 107, 1074, 6006, 6008 -and $_.timecreated -ge [datetime]::today.Adddays(-$arg) } | select-object timecreated, id, InstanceId, message | sort-object -property timecreated | format-list *; get-date }
# set-alias -name ShowShutdownEvent -value fEventShutdown -Option Readonly -force -passthru | format-list
#
Function fjShowEventLog2 {[Alias('ShowEventLog2')] param ()
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    #this is what happens when you don't document something
    #I think this InstanceId are tasks automatically started.
    Get-EventLog -LogName System -InstanceId 1073748869 |
    ForEach-Object {
        [PSCustomObject]@{
            Date      = $_.TimeGenerated
            Name      = $_.ReplacementStrings[0]
            Path      = $_.ReplacementStrings[1]
            StartMode = $_.ReplacementStrings[3]
            User      = $_.ReplacementStrings[4]
        }
    }  | Out-GridView
}
function fjSayIt {
    [Alias('Sayit')] 
    param (
        $Saythis = "",
        $Rate = 2,
        [switch]$Helper
    )
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $Script = (join-path $home\MyStuff speakclipboard.ps1)
    if ($IsCoreClr ) { "Running Pwsh - start Powershell";powershell -noprofile -command  "& {. '$Script' -SayThis '$($SayThis)' -ThisRate $Rate}"}
    else {
        # See https://social.technet.microsoft.com/Forums/scriptcenter/en-US/88903837-b9f2-41ea-986c-b66ce8854587/powershell-startprocess-how-to-start-a-powershell-script-with-arguments?forum=ITCG
        $parameters = @{
            Filepath = "Powershell.exe"
            Args     = " -windowStyle hidden  -nologo -noprofile  -command  & {. '$Script' -SayThis '$($SayThis)' -ThisRate $Rate} "
        }
        start-process @parameters
        # start-process "powershell.exe" -ArgumentList " -windowStyle hidden -noexit -nologo  -command  & {. '$Script' -SayThis '$($SayThis)' -ThisRate $Rate} " 
    }
}
function ShowExplorerHere { 
    # start-process explorer -ArgumentList (get-location)
    invoke-item . 
}

function ShowElevateMe {
    param (
        [ValidateSet("Powershell", "Pwsh", "Cmd")]
        [String] $Task = ""
    )
    Write-Warning "In function $($MyInvocation.MyCommand.Name):2020-11-13 "
    write-warning "Task is <$($Task)>"
    if ($Task -eq "") {if ($PSVersionTable.psedition -eq "Desktop") { $Task="Powershell" }else { $Task="Pwsh" } }
    Start-process "$($Task)" -Verb runas -ArgumentList ""
}

function fjShowScanner {
    [Alias('ShowScanner')]
    param()
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $scan = "C:\Program Files (x86)\Canon\MP Navigator EX 2.0\mpnex20.exe"
    if (Test-Path $scan) {
        start-process $scan; Start-Sleep -seconds 1
        if (get-process mpnex20) { "Patience is a virtue." }else { "Oops!" }
        #explorer 'C:\Users\Super Computer\Pictures\MP Navigator EX\'
        start-process explorer -ArgumentList 'C:\Users\Super Computer\Pictures\MP Navigator EX\'
    }
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
        ($url = $query + $search) #display on console
        Start-Process $url
    }
}#END Search-Google
set-alias -name ShowGoogle -value Search-Google  -option readonly -force #-passthru | format-list


function cdttax {
    set-location $env:home\Dropbox\Private\Tax\TurboTax
}
# Get Last Command - copies the last n commands to the clipboard
Function CopyHistoryCommands($Number) {
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $CommandLength = (Get-History | Measure-Object).Count
    $Start = $CommandLength - $Number + 1
    [array]$CommandRange = @()
    Foreach ($obj in ($Start..$CommandLength)) { $CommandRange += $obj; $obj++ }
    #Foreach ($obj in ($Start .. $CommandLength)) {$CommandRange += $obj}
    (Get-History $CommandRange).CommandLine | Clip
    Write-Host -NoNewline "Last "; Write-Host -NoNewLine -ForegroundColor Green "$($Number) "; Write-Host "commands have been copied to the clipboard."
}

#copy by id to clipboard
function CopyHistoryById {
    param ( [int]$Id = (Get-History -Count 1).Id )
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $history = Get-History -Id $Id -ErrorAction SilentlyContinue -ErrorVariable getHistoryError
    if ($getHistoryError) {
        Write-Warning "$($MyInvocation.MyCommand.Name): $($getHistoryError.Exception.Message)"
    } # if ($getHistoryError) ...
    else {
        $history.CommandLine | clip.exe
    } # if ($getHistoryError) ... else
}
#New-Alias -Force -ErrorAction SilentlyContinue chy Copy-History;

function fjShowDesktop {
    [alias ('ShowDesktop')] param ()
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $x = New-Object -ComObject Shell.Application
    $x.ToggleDesktop()
    $x = $null
}
# set-alias showDesktop -value Show-Desktop -Option Readonly -force -passthru | format-list
#"Version::2019-05-14.0"
function showkeepass {
    start-process ( Join-path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\KeePass 2.lnk" )
}
function ShowMedicalHistory {
    invoke-item (join-path $env:home\onedrive\private\MedicalSpecial "Medical Conditions.docx")
}
function ShowMedicalFolder {
    invoke-item "$env:home\Google Drive\Medical"
}
set-alias ShowWindowsTerminal -value wt.exe -Option Readonly -force #-passthru | format-list

function fjShowWhereIs { [alias ('ShowWhereIs')] param ($arg)
    Write-Warning "In function $($MyInvocation.MyCommand.Name): "
    $dir = $env:Path
    $dir = $dir.split(";") | Sort-Object
    foreach ($path in $dir) { write-host $path }
    Write-host "******"
    #$fullpath=$dir | ForEach-Object {Get-ChildItem $_/$arg}
    $dir  | `
        ForEach-Object { Get-ChildItem -path $_/$arg -File -Force -ErrorAction SilentlyContinue } | sort-object -property $_.directoryname -unique | `
        ForEach-Object `
        -process {
        [pscustomobject]@{
            Name          = $_.name
            Path          = $_.DirectoryName
            LastWriteTime = $_.lastwritetime
        }
    }
}
function ShowWhere ($arg) {
            $paths = where.exe $arg
            If ($lastExitCode -eq 0) { foreach ($path in $paths) { [pscustomobject]@{Name = $arg; Path = split-path -parent $Path } } } else {}
}
filter ShowFileSizeBelow ($size) { if ($_.length -le $size) { $_ } } #ShowFileSizeBelow 1kb
# Harriet
function cdHarriet { Push-Location (join-path $env:OneDrive  "Private\HarrietTrust"); get-childitem -Directory | Select-Object Name }
function cdStartMenu { Push-Location (join-path $env:APPDATA  "Microsoft\Windows\Start Menu\Programs\Windows"); get-childitem -Directory | Select-Object Name }
function showfun { start-process chrome -ArgumentList "http://artii.herokuapp.com/make?text=fRED-aRTHUR+jACOBOWITZ&font=type_set" }
function fjDefineIt {
    [Alias('DefineIt')] param ($word="")
    if ($word -eq "") {$word=(get-clipboard).trim() + " ";$word=$word.Substring(0,$word.indexof(" "));"This was on the clipboard [{0}]" -f $word}
    #  if ($word -eq "") {(get-clipboard).ToCharArray()|foreach-object -begin {$word=$null} -process {if($_ -ne 32){$word+=$_}} -end {"This was on the clipboard [{0}]" -f $word}}
    # if ($word -eq "") {$thistext=(get-clipboard) + " ";$Thistext.ToCharArray()|foreach-object -begin {$word=$null} -process {while([int][char]$_ -ne 32){$word+=$_;$word} } -end {"This was on the clipboard [{0}]" -f $word}}
    $Word="https://www.google.com/search?q=define+" + $word + "&oq=define+" + $word + "&aqs=chrome.0.69i59j0l4.3359j1j7&sourceid=chrome&ie=UTF-8"
    start-process chrome -ArgumentList $word }
function importTestModule {
    [CmdletBinding()]
    param ($Module = "TestScript"
    )
    $env:PSModulePath += ";$home/mystuff/pstest/modules"
    remove-module TestScript
    import-module -verbose $Module
}

<#
https://mcpmag.com/articles/2013/08/13/utilizing-the-as-operator.aspx
'Add Type accelerators'
define type accelerator for type accelerators
    https://blogs.technet.microsoft.com/heyscriptingguy/2013/07/08/use-powershell-to-find-powershell-type-accelerators/
$xlr = [psobject].Assembly.GetType('System.Management.Automation.TypeAccelerators')
$xlr::Add('accelerators', $xlr)
$xlr::Get
[accelerators]::get #simplest way
 #>

<#
[math] | gm -Static"
[System.Environment] | gm -static
ShowWindowsComputerInfo"
get-help -name gci -ShowWindow
show-command -errorPopUp
 #>

 <#
 "Manage App Execution Aliases"
 (new-object Net.WebClient).DownloadString("http://psget.net/GetPsGet.ps1") | iex
  #>

 <#
 Don't use PSReadLine with Powershell ISE
 If(System.Management.Automation.Internal.Host.InternalHost.Name -eq 'ConsoleHost') {import-module -versbose PSReadline}
 If($Host.Name -eq 'ConsoleHost') {import-module -verbose PSReadline}
 #>

 Write-Host "Try Windows Admin Center localhost:6516"
 write-host "https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/overview#introduction"

 <#
 notes
 windows termminal -> Ctrl+Alt+? (ShowKeyBindings)"
 Invoke-Expression (New-Object Net.WebClient).DownloadString("http://bit.ly/e0Mw9w") #rick rolled
 (Invoke-WebRequest 'http://artii.herokuapp.com/make?text=Fred-Arthur Jacobowitz&font=gothic').content
 http://artii.herokuapp.com/make?text=fRED-aRTHUR+ jACOBOWITZ&font=type_set
 #>

 <#
 function ShowPriv {
     $list=whoami /priv
     if ($list|select-string -pattern "SeImpersonatePrivilege" -SimpleMatch -quiet) {write-warning "*** Running as Privilege ***"} else {write-warning "Running no Privilege"}
    }
    ShowPriv
    #>

    "`e[5m{0}" -f "Playground follows"
    write-host `e[5m([System.Globalization.CultureInfo]::CurrentCulture.TextInfo.ToTitleCase("fred-arthur jacobowitz"))
    function showMyWx {
        [CmdletBinding()]
        param ($City = "Hewlett")
        # Invoke-RestMethod -Uri "http://wttr.in/Syracuse?format=2" -UseBasicParsing -DisableKeepAlive
        Invoke-RestMethod -Uri "http://wttr.in/$($City)?format=2" -UseBasicParsing -DisableKeepAlive
    }
    function ShowTestAdministrator {
        Write-Warning "In function $($MyInvocation.MyCommand.Name):2020-11-13 "
        $user = [Security.Principal.WindowsIdentity]::GetCurrent()
        (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    }
    if (ShowTestAdministrator) { write-warning "*** Running as Administrator ***" } else { write-warning "NOT Running as Administrator" }
    if ((get-process "MozillaVPN" ).count -eq 0) {start-process (join-path $env:ProgramData "\Microsoft\Windows\Start Menu\Programs\Mozilla VPN.lnk")}
    # $psStyle
    get-module psreadline |Select-Object name,version,path
    # foreach ($line in 1..5) {for($i=1; $i -lt 155;$i++){write-host -NoNewline ([char](Get-Random -Maximum 122 -Minimum 65))}}
    "Profile specific code ends here"
    write-warning "End of $Temp"; Remove-Variable "ProfileNames"; Remove-Variable "Count"; Remove-Variable Temp
'EOF'


