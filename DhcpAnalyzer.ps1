<#
.SYNOPSIS
  DHCP Analyzer by Starkark98 - read-only health check and interactive dashboard for Windows DHCP servers (IPv4).

.DESCRIPTION
  Opens a small window where you enter the DHCP server name, then analyzes every scope, lease,
  reservation, exclusion (including real usage of excluded IPs), failover relationship and server
  setting, and opens an interactive HTML dashboard with collapsible sections, global search and
  prioritized issues.

  The tool is READ-ONLY: it never changes anything on the DHCP server.

.PARAMETER DhcpServer
  DHCP server to analyze. If omitted, the window asks for it.
.PARAMETER NoGui
  Runs without the window (useful for scheduled tasks).
.PARAMETER SkipExclusionScan
  Skips the network check (ping, TCP, ARP, DNS) of excluded IPs.
.PARAMETER Demo
  Opens a dashboard built from realistic sample data. No DHCP server required.
.PARAMETER OutHtml
  Path of the HTML dashboard. Default: %TEMP%.
.PARAMETER NoElevate
  Does not ask for administrator rights at startup.
.PARAMETER NoOpen
  Saves the dashboard without opening it in the browser (useful with -NoGui in scheduled tasks).
.PARAMETER CompareWith
  Compare mode: the TARGET (new) DHCP server. The source is -DhcpServer (a live server) or -Baseline (a saved file).
  Only configuration is compared (no exclusion scan, no logs). Both servers are only read.
.PARAMETER Baseline
  Compare mode: the SOURCE taken from a file instead of a live server (e.g. an old server that is already switched
  off): a baseline .json saved with -SaveBaseline or the window, or an analysis report .html of DHCP Analyzer.
.PARAMETER SaveBaseline
  Analyze mode: also saves the collected data as a baseline .json (file or folder) for a later comparison.
.PARAMETER DemoCompare
  Opens a compare dashboard built from two sample servers with deliberate differences.

.EXAMPLE
  .\DhcpAnalyzer.ps1
.EXAMPLE
  .\DhcpAnalyzer.ps1 -Demo
.EXAMPLE
  .\DhcpAnalyzer.ps1 -DhcpServer DHCP01 -NoGui -OutHtml C:\Reports\dhcp.html
.EXAMPLE
  .\DhcpAnalyzer.ps1 -DhcpServer DHCP01 -CompareWith DHCP03 -NoGui
.EXAMPLE
  .\DhcpAnalyzer.ps1 -DhcpServer DHCP01 -NoGui -SaveBaseline C:\Reports\
  .\DhcpAnalyzer.ps1 -Baseline C:\Reports\DhcpBaseline_DHCP01_20261022_0900.json -CompareWith DHCP03 -NoGui

.NOTES
  Author : Starkark98
  Credits: developed with the assistance of Claude Code (Anthropic's AI coding assistant),
           under the direction and review of the author.
  License: MIT with the Commons Clause (selling is not permitted) - see the LICENSE file
#>
[CmdletBinding()]
param(
    [string]$DhcpServer,
    [switch]$NoGui,
    [switch]$SkipExclusionScan,
    [switch]$Demo,
    [string]$OutHtml,
    [switch]$NoElevate,
    [switch]$NoOpen,
    [string]$CompareWith,
    [string]$Baseline,
    [string]$SaveBaseline,
    [switch]$DemoCompare
)

$ErrorActionPreference = 'Stop'
$AppName    = 'DHCP Analyzer'
$AppVersion = '1.1.0'

function IpToInt([string]$ip) { $b = [Net.IPAddress]::Parse($ip).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function IntToIp([uint32]$n)  { $b = [BitConverter]::GetBytes($n); [Array]::Reverse($b); [Net.IPAddress]::new([byte[]]$b).ToString() }

# Input validation. A server name is a host name, FQDN or IP address: no spaces, quotes or leading '-'
# (it is passed on the command line when the script relaunches itself with UAC).
function Test-ServerName([string]$name) { $name -match '^[A-Za-z0-9_][A-Za-z0-9._:-]{0,252}$' }
# The report path must be an .html/.htm file; a folder (or a path ending with '\') gets the default file name.
function Resolve-OutHtml([string]$path, [string]$server, [string]$prefix = 'DhcpReport') {
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
    if ($path -match '[\\/]$' -or (Test-Path -LiteralPath $path -PathType Container)) {
        $path = Join-Path $path ("{0}_{1}_{2}.html" -f $prefix, ($server -replace '[^\w.-]', '_'), (Get-Date -Format yyyyMMdd_HHmmss))
    }
    if ([IO.Path]::GetExtension($path) -notmatch '^\.html?$') { throw "The report path must end with .html or .htm: $path" }
    $path
}

# ---- Baselines: the data of an analysis saved as .json, used later as the source of a comparison ----
function Resolve-BaselinePath([string]$path, [string]$server) {
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
    if ($path -match '[\\/]$' -or (Test-Path -LiteralPath $path -PathType Container)) {
        $path = Join-Path $path ("DhcpBaseline_{0}_{1}.json" -f ($server -replace '[^\w.-]', '_'), (Get-Date -Format yyyyMMdd_HHmm))
    }
    if ([IO.Path]::GetExtension($path) -ne '.json') { throw "The baseline path must end with .json: $path" }
    $path
}
function Save-Baseline([string]$json, [string]$server, [string]$path) {
    $path = Resolve-BaselinePath $path $server
    $dir  = Split-Path $path -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item $dir -ItemType Directory -Force) }
    $head = [ordered]@{ tool = 'DhcpAnalyzer'; version = $AppVersion; saved = (Get-Date).ToString('yyyy-MM-dd HH:mm'); server = $server } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($path, $head.Substring(0, $head.Length - 1) + ',"data":' + $json + '}', [Text.UTF8Encoding]::new($false))
    $path
}
function Get-JsonSerializer {
    Add-Type -AssemblyName System.Web.Extensions
    $s = [Web.Script.Serialization.JavaScriptSerializer]::new(); $s.MaxJsonLength = [int]::MaxValue; $s.RecursionLimit = 64; $s
}
# A baseline is untrusted input: a .json saved by DHCP Analyzer, or one of its analysis reports (.html/.htm).
# Its data is parsed and serialized again, never pasted into a report as it is.
# 'partial' = created before 1.1.0 (no policies, classes, option definitions, superscopes): those are not compared.
function Read-Baseline([string]$path) {
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Baseline file not found: $path" }
    $ser  = Get-JsonSerializer
    $text = [IO.File]::ReadAllText($path)
    if ([IO.Path]::GetExtension($path) -match '^\.html?$') {
        $title = [regex]::Match($text, '<title>([^<]*)</title>').Groups[1].Value.Trim()
        if ($title -match '^(.+?) by Starkark98' -and $Matches[1] -ne 'DHCP Analyzer') { throw "This report was created by $($Matches[1]), not by DHCP Analyzer: $path" }   # a sibling tool
        $a = $text.IndexOf('const D='); $b = if ($a -ge 0) { $text.IndexOf(', WARN=80, CRIT=95;', $a) } else { -1 }
        if ($title -notmatch '^DHCP Analyzer\b' -or $a -lt 0 -or $b -lt 0) { throw "Not a DHCP Analyzer report: $path" }
        try { $d = $ser.DeserializeObject($text.Substring($a + 8, $b - $a - 8)) } catch { throw "The report file is incomplete or damaged: $path" }
        if ($d -is [Collections.IDictionary] -and "$($d['mode'])" -eq 'compare') { throw "This is a comparison report: choose the report of an analysis, or a baseline .json: $path" }
        if (-not ($d -is [Collections.IDictionary]) -or -not $d.ContainsKey('scopes')) { throw "The report file is incomplete or damaged: $path" }
        return [pscustomobject]@{ kind = 'report'; server = "$($d['server'])"; saved = "$($d['generated'])"; version = ''; partial = (-not $d.ContainsKey('policies')); json = $ser.Serialize($d) }
    }
    try { $o = $ser.DeserializeObject($text) } catch { throw "Not a valid baseline file (it is not JSON): $path" }
    if (-not ($o -is [Collections.IDictionary]) -or -not "$($o['tool'])") { throw "The baseline file is incomplete or damaged: $path" }
    if ("$($o['tool'])" -ne 'DhcpAnalyzer') { throw "This baseline was saved by $($o['tool']), not by DHCP Analyzer: $path" }
    if (-not ($o['data'] -is [Collections.IDictionary]) -or -not $o['data'].ContainsKey('scopes')) { throw "The baseline file is incomplete or damaged: $path" }
    [pscustomobject]@{ kind = 'baseline'; server = "$($o['server'])"; saved = "$($o['saved'])"; version = "$($o['version'])"; partial = (-not $o['data'].ContainsKey('policies')); json = $ser.Serialize($o['data']) }
}
# Compare data for the dashboard: { mode, aKind (server|baseline|report), aSaved, aPartial, demo, a: source data, b: target data }
function New-CompareJson([string]$srcJson, [string]$tgtJson, [string]$srcKind = 'server', [string]$srcSaved = '', [bool]$demo = $false, [bool]$partial = $false) {
    $meta = [ordered]@{ mode = 'compare'; aKind = $srcKind; aSaved = $srcSaved; aPartial = $partial; demo = $demo } | ConvertTo-Json -Compress
    $meta.Substring(0, $meta.Length - 1) + ',"a":' + $srcJson + ',"b":' + $tgtJson + '}'
}
# Compare data when the source is a baseline or report read with Read-Baseline
function New-CompareJsonFromBaseline($base, [string]$tgtJson) { New-CompareJson $base.json $tgtJson $base.kind $base.saved $false ([bool]$base.partial) }

# =============================================================================
#  ANALYSIS ENGINE (runs in a background runspace)
# =============================================================================
$Collector = {
    param($Server, $Scan, $Sync, $Light)   # $Light: configuration only (no exclusion scan, no logs), used by Compare
    $ErrorActionPreference = 'Stop'
    try {
        Import-Module DhcpServer -ErrorAction Stop

        function IpToInt([string]$ip) { $b = [Net.IPAddress]::Parse($ip).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
        function IntToIp([uint32]$n)  { $b = [BitConverter]::GetBytes($n); [Array]::Reverse($b); [Net.IPAddress]::new([byte[]]$b).ToString() }
        function Safe([scriptblock]$sb) { try { & $sb } catch { } }
        function P($o, [string[]]$names) { foreach ($n in $names) { if ($null -ne $o.$n) { return $o.$n } }; 0 }
        function Span($ts) { if ($null -eq $ts) { return '' }; if ($ts.TotalDays -ge 1) { '{0:0.#} d' -f $ts.TotalDays } else { '{0:0.#} h' -f $ts.TotalHours } }
        function Dt($d) { if ($d -is [datetime]) { $d.ToString('yyyy-MM-dd HH:mm') } else { '' } }
        function Step($msg, $pct) { $Sync.Status = $msg; if ($null -ne $pct) { $Sync.Progress = [int]$pct } }

        $Ports    = @(22, 80, 135, 443, 445, 3389, 9100)
        $Passes   = 3
        $localIps = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { IpToInt $_.IPAddress })

        function Scan-Exclusions($sc, $ex, $rs) {
            $resv = @{}; foreach ($r in $rs) { $resv[$r.IPAddress.ToString()] = $r }
            $size = 0; foreach ($e in $ex) { $size += [int64](IpToInt $e.EndRange) - [int64](IpToInt $e.StartRange) + 1 }
            if ($size -gt 1024) { return [pscustomobject]@{ arp = $false; skipped = $true; ips = @() } }
            $ips  = @(foreach ($e in $ex) { for ($n = IpToInt $e.StartRange; $n -le (IpToInt $e.EndRange); $n++) { IntToIp $n } })

            $mask   = IpToInt $sc.SubnetMask
            $net    = (IpToInt $sc.ScopeId) -band $mask
            $sameL2 = @($localIps | Where-Object { ($_ -band $mask) -eq $net }).Count -gt 0

            # Ping (several passes, asynchronous)
            $alive = @{}
            for ($p = 1; $p -le $Passes; $p++) {
                $pending = @{}; $pingers = [Collections.Generic.List[object]]::new()
                foreach ($ip in $ips) { if (-not $alive.ContainsKey($ip)) { $pg = [Net.NetworkInformation.Ping]::new(); $pingers.Add($pg); $pending[$ip] = $pg.SendPingAsync($ip, 1000) } }
                if ($pending.Count -eq 0) { break }
                try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($pending.Values)) } catch { }
                foreach ($k in $pending.Keys) { $t = $pending[$k]; if ($t.Status -eq 'RanToCompletion' -and $t.Result.Status -eq 'Success') { $alive[$k] = [int]$t.Result.RoundtripTime } }
                foreach ($pg in $pingers) { $pg.Dispose() }
            }

            # TCP connect on hosts that ignore ping
            $tcp  = @{}
            $todo = @($ips | Where-Object { -not $alive.ContainsKey($_) })
            for ($i = 0; $i -lt $todo.Count; $i += 64) {
                $probes = foreach ($ip in $todo[$i..([math]::Min($i + 63, $todo.Count - 1))]) {
                    foreach ($port in $Ports) { $c = [Net.Sockets.TcpClient]::new(); [pscustomobject]@{ IP = $ip; Port = $port; Client = $c; Task = $c.ConnectAsync($ip, $port) } }
                }
                try { [void][Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($probes.Task), 1000) } catch { }
                foreach ($pr in $probes) {
                    if ($pr.Task.Status -eq 'RanToCompletion') { $tcp[$pr.IP] = (@($tcp[$pr.IP]) + $pr.Port | Where-Object { $_ -and $_ -ne 'refused' }) -join ',' }
                    elseif ($pr.Task.IsFaulted -and $pr.Task.Exception.InnerException.SocketErrorCode -eq 'ConnectionRefused' -and -not $tcp[$pr.IP]) { $tcp[$pr.IP] = 'refused' }
                    $pr.Client.Dispose()
                }
            }

            # ARP table (catches hosts with a firewall blocking ICMP, same subnet only)
            $arp = @{}
            if ($sameL2) {
                Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                    Where-Object { $_.State -notin 'Unreachable', 'Incomplete' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' } |
                    ForEach-Object { $arp[$_.IPAddress] = $_.LinkLayerAddress }
            }

            $out = foreach ($ip in $ips) {
                $ptr  = Safe { (Resolve-DnsName $ip -Type PTR -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue | Where-Object Type -eq 'PTR' | Select-Object -First 1).NameHost }
                $r    = $resv[$ip]
                $live = $alive.ContainsKey($ip) -or $tcp.ContainsKey($ip) -or $arp.ContainsKey($ip)
                [pscustomobject]@{
                    ip   = $ip
                    cls  = $(if ($live) { 'occ' } elseif ($ptr -or $r) { 'chk' } else { 'free' })
                    ping = $(if ($alive.ContainsKey($ip)) { $alive[$ip] } else { '' })
                    tcp  = "$($tcp[$ip])"; mac = "$($arp[$ip])"; dns = "$ptr"
                    resv = $(if ($r) { "$($r.Name)" } else { '' })
                }
            }
            [pscustomobject]@{ arp = $sameL2; skipped = $false; ips = @($out) }
        }

        # ---- Server ----
        Step "Connecting to $Server..." 2
        $cands = @($Server)
        if ($Server -notmatch '^\d+\.\d+\.\d+\.\d+$' -and $Server.Contains('.')) { $cands += $Server.Split('.')[0] }
        $scopes = $null; $firstErr = $null
        foreach ($cand in $cands) {
            try { $scopes = @(Get-DhcpServerv4Scope -ComputerName $cand | Sort-Object { IpToInt $_.ScopeId }); $Server = $cand; break }
            catch { if (-not $firstErr) { $firstErr = $_ } }
        }
        if ($null -eq $scopes) { throw $firstErr }

        Step 'Reading server configuration...' 5
        $setting = Safe { Get-DhcpServerSetting       -ComputerName $Server }
        $db      = Safe { Get-DhcpServerDatabase      -ComputerName $Server }
        $audit   = Safe { Get-DhcpServerAuditLog      -ComputerName $Server }
        $dnsSet  = Safe { Get-DhcpServerv4DnsSetting  -ComputerName $Server }
        $dnsCred = Safe { Get-DhcpServerDnsCredential -ComputerName $Server }
        $fo      = @(Safe { Get-DhcpServerv4Failover  -ComputerName $Server } | Where-Object { $_ })
        $srvOpt  = @(Safe { Get-DhcpServerv4OptionValue -ComputerName $Server } | Where-Object { $_ })
        $srvMap  = @{}; foreach ($o in $srvOpt) { $srvMap[[int]$o.OptionId] = $o }
        $stats   = @{}; Safe { Get-DhcpServerv4ScopeStatistics -ComputerName $Server } | Where-Object { $_ } | ForEach-Object { $stats[$_.ScopeId.ToString()] = $_ }
        $svc     = Safe { Get-Service -ComputerName $Server -Name DHCPServer }
        $ver     = Safe { Get-DhcpServerVersion -ComputerName $Server }
        $fList   = Safe { Get-DhcpServerv4FilterList -ComputerName $Server }
        $filters = @(Safe { Get-DhcpServerv4Filter -ComputerName $Server } | Where-Object { $_ })

        # ---- Policies, classes, option definitions, superscopes ----
        Step 'Reading policies, classes and option definitions...' 7
        function Opts($list) { @($list | Where-Object { $_ } | Sort-Object OptionId | ForEach-Object { [pscustomobject]@{ id = [int]$_.OptionId; name = "$($_.Name)"; value = (@($_.Value) -join ', '); vendor = "$($_.VendorClass)" } }) }
        function Policies([string]$scopeId) {
            $pl = @(Safe { if ($scopeId) { Get-DhcpServerv4Policy -ComputerName $Server -ScopeId $scopeId } else { Get-DhcpServerv4Policy -ComputerName $Server } } | Where-Object { $_ -and $_.Name })
            @($pl | Sort-Object ProcessingOrder | ForEach-Object {
                $p = $_
                $cond = foreach ($k in 'VendorClass', 'UserClass', 'MacAddress', 'ClientId', 'Fqdn', 'RelayAgent', 'CircuitId', 'RemoteId', 'SubscriberId') {
                    $v = @($p.$k | Where-Object { "$_" }); if ($v.Count) { "$k " + ($v -join ' ') } }
                $po = Safe { if ($scopeId) { Get-DhcpServerv4OptionValue -ComputerName $Server -ScopeId $scopeId -PolicyName $p.Name } else { Get-DhcpServerv4OptionValue -ComputerName $Server -PolicyName $p.Name } }
                $pr = if ($scopeId) { @(Safe { Get-DhcpServerv4PolicyIPRange -ComputerName $Server -ScopeId $scopeId -Name $p.Name } | Where-Object { $_ } | ForEach-Object { "$($_.StartRange)-$($_.EndRange)" }) } else { @() }
                [pscustomobject]@{ name = "$($p.Name)"; enabled = [bool]$p.Enabled; order = [int]$p.ProcessingOrder; logic = "$($p.Condition)"
                    conditions = (@($cond) -join '; '); lease = (Span $p.LeaseDuration); desc = "$($p.Description)"; ranges = ($pr -join ', '); options = @(Opts $po) }   # @(): an empty result would serialize as {} in PS 5.1
            })
        }
        $srvPol   = Policies ''
        $classes  = @(Safe { Get-DhcpServerv4Class -ComputerName $Server } | Where-Object { $_ -and $_.Name } | Sort-Object Type, Name | ForEach-Object {
            [pscustomobject]@{ name = "$($_.Name)"; type = "$($_.Type)"; data = $(if ("$($_.AsciiData)") { "$($_.AsciiData)" } else { "$($_.Data)" }); desc = "$($_.Description)" } })
        $optDefs  = @(Safe { Get-DhcpServerv4OptionDefinition -ComputerName $Server -All } | Where-Object { $_ } | Sort-Object VendorClass, OptionId | ForEach-Object {
            [pscustomobject]@{ id = [int]$_.OptionId; name = "$($_.Name)"; type = "$($_.Type)"; vendor = "$($_.VendorClass)"; multi = [bool]$_.MultiValued; def = (@($_.DefaultValue) -join ', '); desc = "$($_.Description)" } })
        $supers   = @(Safe { Get-DhcpServerv4Superscope -ComputerName $Server } | Where-Object { $_ -and "$($_.SuperscopeName)" } | ForEach-Object {
            [pscustomobject]@{ name = "$($_.SuperscopeName)"; scopes = @($_.ScopeId | ForEach-Object { $_.ToString() }) } })

        $logInfo = $null
        if (-not $Light) {
            # ---- Event logs and audit log (last 7 days) ----
            Step 'Reading DHCP event logs and audit log...' 8
            $since = (Get-Date).Date.AddDays(-6)
            $events = @(); $evErr = ''
            $evFilters = @(
                @{ LogName = 'Microsoft-Windows-Dhcp-Server/Admin';       Level = 1, 2, 3; StartTime = $since },
                @{ LogName = 'Microsoft-Windows-Dhcp-Server/Operational'; Level = 1, 2, 3; StartTime = $since },
                @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-DHCP-Server'; Level = 1, 2, 3; StartTime = $since },
                @{ LogName = 'System'; ProviderName = 'DhcpServer';                    Level = 1, 2, 3; StartTime = $since })
            foreach ($f in $evFilters) {
                try { $events += @(Get-WinEvent -ComputerName $Server -FilterHashtable $f -MaxEvents 1000 -ErrorAction Stop) }
                catch { if ("$($_.FullyQualifiedErrorId)" -notmatch 'NoMatching') { $evErr = $_.Exception.Message } }
            }
            $evGroups = @($events | Group-Object { "$($_.LogName)|$($_.Id)|$($_.Level)" } | ForEach-Object {
                $g = @($_.Group | Sort-Object TimeCreated -Descending)
                $m = (("$($g[0].Message)" -split "`r?`n") | Where-Object { $_.Trim() } | Select-Object -First 2) -join ' '
                if (-not $m) { $m = '(no description available)' } elseif ($m.Length -gt 300) { $m = $m.Substring(0, 300) + '...' }
                [pscustomobject]@{ log = ($g[0].LogName -replace '^Microsoft-Windows-Dhcp-Server/', 'DHCP '); id = [int]$g[0].Id; level = [int]$g[0].Level; count = $_.Count
                    first = $g[-1].TimeCreated.ToString('yyyy-MM-dd HH:mm'); last = $g[0].TimeCreated.ToString('yyyy-MM-dd HH:mm'); msg = $m }
            } | Sort-Object @{ e = 'level' }, @{ e = 'count'; Descending = $true })

            $days = [ordered]@{}
            for ($d = 0; $d -le 6; $d++) { $days[$since.AddDays($d).ToString('yyyy-MM-dd')] = [ordered]@{ new = 0; renew = 0; release = 0; conflict = 0; full = 0; denied = 0; dnsfail = 0 } }
            $auRows = [Collections.Generic.List[object]]::new(); $auErr = ''
            if (-not $audit) { $auErr = 'Audit log settings could not be read.' }
            elseif (-not $audit.Enable) { $auErr = 'Audit log is disabled on the server.' }
            else {
                try {
                    $aPath   = ([string]$audit.Path) -replace '(?i)%windir%|%systemroot%', 'C:\Windows'
                    # The path comes from the server's configuration: accept only a local drive path. A UNC path
                    # (\\otherhost\share) would make this PC connect to another host with the current user's credentials.
                    if ($aPath -notmatch '^[A-Za-z]:\\[^:*?"<>|]*$' -or $aPath -match '\\\.\.(\\|$)') { throw "Unsupported audit log path on the server: $aPath" }
                    $isLocal = ($Server -in @('localhost', '127.0.0.1', '.', $env:COMPUTERNAME)) -or ($Server -like "$env:COMPUTERNAME.*")
                    $aDir    = if ($isLocal) { $aPath } else { "\\$Server\" + ($aPath -replace '^([A-Za-z]):', '$1$') }
                    $ci      = [Globalization.CultureInfo]::InvariantCulture
                    foreach ($file in @(Get-ChildItem -LiteralPath $aDir -Filter 'DhcpSrvLog-*.log' -File -ErrorAction Stop)) {
                        if ($file.LastWriteTime -lt $since) { continue }
                        $sr = [IO.StreamReader]::new([IO.File]::Open($file.FullName, 'Open', 'Read', 'ReadWrite'))
                        try {
                            while ($null -ne ($line = $sr.ReadLine())) {
                                if ($line -notmatch '^\d{2},') { continue }
                                $c = $line.Split(','); if ($c.Count -lt 7) { continue }
                                $dt = [datetime]::MinValue
                                if (-not [datetime]::TryParseExact("$($c[1]) $($c[2])", 'MM/dd/yy HH:mm:ss', $ci, 'None', [ref]$dt)) { continue }
                                $key = $dt.ToString('yyyy-MM-dd'); if (-not $days.Contains($key)) { continue }
                                $id = [int]$c[0]
                                $k = switch ($id) { 10 { 'new' } 11 { 'renew' } 12 { 'release' } 13 { 'conflict' } 14 { 'full' } 15 { 'denied' } 31 { 'dnsfail' } 34 { 'dnsfail' } 35 { 'dnsfail' } }
                                if ($k) { $days[$key][$k]++ }
                                if ($id -in 13, 14, 15, 31, 34, 35) { $auRows.Add([pscustomobject]@{ time = $dt.ToString('yyyy-MM-dd HH:mm:ss'); id = $id; desc = $c[3]; ip = $c[4]; host = $c[5]; mac = $c[6] }) }
                            }
                        } finally { $sr.Close() }
                    }
                } catch { $auErr = $_.Exception.Message }
            }
            $logInfo = [pscustomobject]@{
                eventsErr = $evErr; events = $evGroups; auditErr = $auErr
                days = @(foreach ($k in $days.Keys) { [pscustomobject]$days[$k] | Add-Member -NotePropertyName day -NotePropertyValue $k -PassThru })
                rows = @($auRows | Sort-Object time -Descending | Select-Object -First 500)
            }
        }

        # ---- Scopes ----
        $n = 0; $tot = [math]::Max($scopes.Count, 1)
        $scopeOut = foreach ($sc in $scopes) {
            $n++; $id = $sc.ScopeId.ToString()
            $base = 12 + [int](84 * ($n - 1) / $tot)
            Step "Scope $id ($n of $tot): leases, reservations, options" $base

            $st    = $stats[$id]
            $soMap = @{}; Safe { Get-DhcpServerv4OptionValue -ComputerName $Server -ScopeId $id } | Where-Object { $_ } | ForEach-Object { $soMap[[int]$_.OptionId] = $_ }
            $opts  = foreach ($oid in (@($soMap.Keys) + @($srvMap.Keys) | Sort-Object -Unique)) {
                $o = if ($soMap.ContainsKey($oid)) { $soMap[$oid] } else { $srvMap[$oid] }
                [pscustomobject]@{ id = [int]$oid; name = "$($o.Name)"; value = (@($o.Value) -join ', '); inherited = (-not $soMap.ContainsKey($oid)) }
            }
            $ex  = @(Safe { Get-DhcpServerv4ExclusionRange -ComputerName $Server -ScopeId $id } | Where-Object { $_ } | Sort-Object { IpToInt $_.StartRange })
            $rs  = @(Safe { Get-DhcpServerv4Reservation    -ComputerName $Server -ScopeId $id } | Where-Object { $_ })
            $ls  = if ($Light) { @() } else { @(Safe { Get-DhcpServerv4Lease -ComputerName $Server -ScopeId $id -AllLeases } | Where-Object { $_ }) }
            $pol = Policies $id
            $foR = $fo | Where-Object { @($_.ScopeId | ForEach-Object { $_.ToString() }) -contains $id } | Select-Object -First 1

            $scanRes = $null
            if ($Scan -and $ex.Count -and "$($sc.State)" -eq 'Active') {
                Step "Scope ${id}: checking real usage of excluded IPs (ping, ports, ARP, DNS)" ($base + [int](44 / $tot))
                $scanRes = Scan-Exclusions $sc $ex $rs
            }

            [pscustomobject]@{
                id = $id; name = "$($sc.Name)"; desc = "$($sc.Description)"; active = ("$($sc.State)" -eq 'Active')
                mask = $sc.SubnetMask.ToString(); start = $sc.StartRange.ToString(); end = $sc.EndRange.ToString()
                lease = (Span $sc.LeaseDuration)
                inUse = [int](P $st 'InUse', 'AddressesInUse'); free = [int](P $st 'Free', 'AddressesFree')
                failover = $(if ($foR) { "$($foR.Name)" } else { '' })
                options = @($opts)
                exclusions = @($ex | ForEach-Object { [pscustomobject]@{ start = $_.StartRange.ToString(); end = $_.EndRange.ToString(); count = [int]([int64](IpToInt $_.EndRange) - [int64](IpToInt $_.StartRange) + 1) } })
                reservations = @($rs | ForEach-Object { [pscustomobject]@{ ip = $_.IPAddress.ToString(); name = "$($_.Name)"; mac = "$($_.ClientId)"; type = "$($_.Type)"; desc = "$($_.Description)" } })
                leases = @($ls | ForEach-Object { [pscustomobject]@{ ip = $_.IPAddress.ToString(); host = "$($_.HostName)"; mac = "$($_.ClientId)"; state = "$($_.AddressState)"; expiry = (Dt $_.LeaseExpiryTime) } })
                policies = @($pol)
                scan = $scanRes
            }
        }

        Step 'Building dashboard...' 97
        $data = [pscustomobject]@{
            server = $Server; generated = (Get-Date).ToString('yyyy-MM-dd HH:mm'); scanned = [bool]$Scan; demo = $false; light = [bool]$Light
            settings = [pscustomobject]@{
                authorized = $(if ($setting) { [bool]$setting.IsAuthorized } else { $null })
                conflict   = $(if ($setting) { [int]$setting.ConflictDetectionAttempts } else { $null })
                auditOn    = $(if ($audit) { [bool]$audit.Enable } else { $null }); auditPath = "$($audit.Path)"
                backupPath = "$($db.BackupPath)"; backupInt = "$($db.BackupInterval)"
                dnsDyn     = "$($dnsSet.DynamicUpdates)"
                dnsDel     = $(if ($dnsSet) { [bool]$dnsSet.DeleteDnsRROnLeaseExpiry } else { $null })
                nameProt   = $(if ($dnsSet) { [bool]$dnsSet.NameProtection } else { $null })
                dnsCred    = $(if ($dnsCred.UserName) { "$($dnsCred.DomainName)\$($dnsCred.UserName)" } else { '' })
                service    = "$($svc.Status)"; startType = "$($svc.StartType)"
                version    = $(if ($ver) { "$($ver.MajorVersion).$($ver.MinorVersion)" } else { '' })
                allowOn    = [bool]$fList.Allow; denyOn = [bool]$fList.Deny
                allowN     = @($filters | Where-Object { "$($_.List)" -eq 'Allow' }).Count; denyN = @($filters | Where-Object { "$($_.List)" -eq 'Deny' }).Count
            }
            serverOptions = @($srvOpt | Sort-Object OptionId | ForEach-Object { [pscustomobject]@{ id = [int]$_.OptionId; name = "$($_.Name)"; value = (@($_.Value) -join ', ') } })
            failover = @($fo | ForEach-Object { [pscustomobject]@{
                name = "$($_.Name)"; partner = "$($_.PartnerServer)"; mode = "$($_.Mode)"; state = "$($_.State)"; role = "$($_.ServerRole)"
                mclt = (Span $_.MaxClientLeadTime); lb = "$($_.LoadBalancePercent)"; reserve = "$($_.ReservePercent)"
                auto = [bool]$_.AutoStateTransition; switchInt = (Span $_.StateSwitchInterval); scopes = @($_.ScopeId | ForEach-Object { $_.ToString() }) } })
            policies = @($srvPol); classes = @($classes); optionDefs = @($optDefs); superscopes = @($supers)
            scopes = @($scopeOut)
            logs = $logInfo
        }
        $Sync.Json = ($data | ConvertTo-Json -Depth 8 -Compress)
        Step 'Analysis completed' 100
    }
    catch {
        $msg  = $_.Exception.Message
        $fqid = "$($_.FullyQualifiedErrorId)"
        $all  = "$msg $fqid $($_.Exception.InnerException.Message)"
        $admin = $false
        try { $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
        $hint = if ($all -match 'WIN32 5\b|Access is denied') {
            'ACCESS DENIED. ' + $(if (-not $admin) { 'The program is not running as administrator: restart it and accept the UAC prompt. ' } else { '' }) +
            "Make sure $env:USERDOMAIN\$env:USERNAME is a member of 'DHCP Users' or 'DHCP Administrators' on the server."
        } elseif ($all -match 'WIN32 1722|WIN32 1753|RPC') {
            'RPC SERVER UNAVAILABLE: check the server name/DNS, that the DHCP service is running and that the firewall allows RPC (135 + dynamic ports).'
        } elseif ($all -match 'WIN32 1355|WIN32 53\b|WIN32 1311') {
            'SERVER NOT FOUND: check the server name and DNS resolution.'
        } elseif ($all -match 'Modules_ModuleNotFound|module .DhcpServer. was not loaded') {
            'DhcpServer module not found: install the RSAT "DHCP Server Tools" on this PC.'
        } else {
            "Running as administrator: $(if ($admin) { 'yes' } else { 'no' }). Try in PowerShell: Get-DhcpServerv4Scope -ComputerName $Server"
        }
        $Sync.Error = "$msg [$fqid]`r`n$hint"
    }
    finally { $Sync.Done = $true }
}

# =============================================================================
#  DEMO DATA (realistic, fictitious)
# =============================================================================
function New-DemoData {
    $rnd = [Random]::new(2026)
    $now = Get-Date
    $dom = 'contoso.local'
    function Mac { (1..6 | ForEach-Object { '{0:x2}' -f $rnd.Next(256) }) -join '-' }
    function Range([string]$a, [string]$b) { for ($n = IpToInt $a; $n -le (IpToInt $b); $n++) { IntToIp $n } }
    function Lease([string]$ip, [string]$hn, [string]$state, [int]$hours) {
        [pscustomobject]@{ ip = $ip; host = $hn; mac = (Mac); state = $state; expiry = $now.AddHours($hours).ToString('yyyy-MM-dd HH:mm') }
    }
    function Dyn([string[]]$ips, [string[]]$prefixes, [int]$active, [int]$expired, [int]$bad) {
        $bads = @{}; while ($bads.Count -lt $bad) { $bads[$rnd.Next($active)] = $true }
        for ($i = 0; $i -lt $ips.Count -and $i -lt ($active + $expired); $i++) {
            if ($bads.ContainsKey($i)) { Lease $ips[$i] 'BAD_ADDRESS' 'Declined' $rnd.Next(1, 24); continue }
            $hn = ('{0}-{1:0000}.{2}' -f $prefixes[$rnd.Next($prefixes.Count)], $rnd.Next(10, 9999), $dom).ToLower()
            if ($i -lt $active) { Lease $ips[$i] $hn 'Active' $rnd.Next(2, 190) } else { Lease $ips[$i] $hn 'Expired' (-$rnd.Next(1, 48)) }
        }
    }
    function Opt([int]$id, [string]$name, [string]$value, [bool]$inh) { [pscustomobject]@{ id = $id; name = $name; value = $value; inherited = $inh } }
    function Excl([string]$a, [string]$b) { [pscustomobject]@{ start = $a; end = $b; count = [int]((IpToInt $b) - (IpToInt $a) + 1) } }
    function Scope($id, $name, $desc, $active, $mask, $start, $end, $lease, $inUse, $exN, $fo, $opts, $ex, $rs, $ls, $scan) {
        $size = [int]((IpToInt $end) - (IpToInt $start) + 1)
        [pscustomobject]@{ id = $id; name = $name; desc = $desc; active = $active; mask = $mask; start = $start; end = $end; lease = $lease
            inUse = $inUse; free = ($size - $exN - $inUse); failover = $fo; options = @($opts); exclusions = @($ex)
            reservations = @($rs); leases = @($ls); policies = @(); scan = $scan }
    }
    function Pol($name, $order, $cond, $ranges, $opts, $lease = '', $enabled = $true) {
        [pscustomobject]@{ name = $name; enabled = $enabled; order = $order; logic = 'Or'; conditions = $cond; lease = $lease; desc = ''; ranges = $ranges
            options = @($opts | ForEach-Object { [pscustomobject]@{ id = $_[0]; name = $_[1]; value = $_[2]; vendor = '' } }) }
    }
    $srvDns = Opt 6 'DNS Servers' '10.10.0.10, 10.10.0.11' $true
    $srvDom = Opt 15 'DNS Domain Name' $dom $true

    # 1 - HQ clients: high utilization, a couple of conflicts
    $ips = @(Range '10.10.0.20' '10.10.1.250')
    $s1 = Scope '10.10.0.0' 'HQ-Clients' 'Head office workstations and laptops' $true '255.255.254.0' '10.10.0.20' '10.10.1.250' '8 d' 432 0 'dhcp01-dhcp02' `
        @((Opt 3 'Router' '10.10.0.1' $false), $srvDns, $srvDom) @() @() (Dyn $ips @('WS', 'LT', 'MAC') 432 26 2) $null

    # 2 - Printers & IoT: reservations + exclusion with real usage map
    $rs2 = @(); $ls2 = @()
    for ($i = 1; $i -le 18; $i++) {
        $ip = "10.10.8.$(9 + $i)"; $nm = 'PRN-FLOOR{0}-{1:00}' -f [math]::Ceiling($i / 6), $i
        $rs2 += [pscustomobject]@{ ip = $ip; name = $nm; mac = (Mac); type = 'Dhcp'; desc = 'Network printer' }
        if ($i -notin 5, 11, 17) { $ls2 += Lease $ip ($nm.ToLower() + ".$dom") 'ActiveReservation' 160 } else { $ls2 += [pscustomobject]@{ ip = $ip; host = ''; mac = ''; state = 'InactiveReservation'; expiry = '' } }
    }
    $ls2 += Dyn @(Range '10.10.8.30' '10.10.8.137') @('IOT-SENSOR', 'BADGE', 'TV') 102 4 0
    $scanIps = foreach ($n in 138..200) {
        $ip = "10.10.8.$n"
        if ($n -le 152)     { [pscustomobject]@{ ip = $ip; cls = 'occ'; ping = $rnd.Next(1, 4); tcp = ''; mac = (Mac); dns = $(if ($n -le 141) { "sw-core-0$($n - 137).$dom" } else { "ap-floor$([math]::Ceiling(($n - 141) / 4))-$('{0:00}' -f ($n - 141)).$dom" }); resv = '' } }
        elseif ($n -le 160) { [pscustomobject]@{ ip = $ip; cls = 'occ'; ping = ''; tcp = '443'; mac = (Mac); dns = "cam-$('{0:00}' -f ($n - 152)).$dom"; resv = '' } }
        elseif ($n -le 175) { [pscustomobject]@{ ip = $ip; cls = 'free'; ping = ''; tcp = ''; mac = ''; dns = ''; resv = '' } }
        elseif ($n -le 181) { [pscustomobject]@{ ip = $ip; cls = 'occ'; ping = $rnd.Next(1, 3); tcp = '80,443'; mac = (Mac); dns = "ups-0$($n - 175).$dom"; resv = '' } }
        elseif ($n -eq 182) { [pscustomobject]@{ ip = $ip; cls = 'chk'; ping = ''; tcp = ''; mac = ''; dns = "old-nas.$dom"; resv = '' } }
        else                { [pscustomobject]@{ ip = $ip; cls = 'free'; ping = ''; tcp = ''; mac = ''; dns = ''; resv = '' } }
    }
    $s2 = Scope '10.10.8.0' 'Printers-IoT' 'Printers, sensors, cameras' $true '255.255.255.0' '10.10.8.2' '10.10.8.252' '8 d' 117 63 'dhcp01-dhcp02' `
        @((Opt 3 'Router' '10.10.8.1' $false), $srvDns, $srvDom) @(Excl '10.10.8.138' '10.10.8.200') $rs2 $ls2 ([pscustomobject]@{ arp = $true; skipped = $false; ips = @($scanIps) })

    # 3 - Branch office: almost full and not protected by failover
    $s3 = Scope '10.20.0.0' 'Branch-Milan' 'Milan branch office' $true '255.255.255.0' '10.20.0.10' '10.20.0.240' '8 d' 225 0 '' `
        @((Opt 3 'Router' '10.20.0.1' $false), $srvDns, $srvDom) @() @() (Dyn @(Range '10.20.0.10' '10.20.0.240') @('MI-WS', 'MI-LT') 225 3 0) $null

    # 4 - Guest Wi-Fi: short lease, public DNS
    $s4 = Scope '10.30.0.0' 'Guest-WiFi' 'Isolated guest network' $true '255.255.255.0' '10.30.0.10' '10.30.0.250' '4 h' 95 0 'dhcp01-dhcp02' `
        @((Opt 3 'Router' '10.30.0.1' $false), (Opt 6 'DNS Servers' '1.1.1.1, 8.8.8.8' $false), $srvDom) @() @() (Dyn @(Range '10.30.0.10' '10.30.0.250') @('android', 'iphone', 'guest') 95 41 0) $null

    # 5 - VoIP: gateway option missing
    $s5 = Scope '10.40.0.0' 'VoIP-Phones' 'IP phones' $true '255.255.255.0' '10.40.0.20' '10.40.0.200' '8 d' 60 0 'dhcp01-dhcp02' `
        @($srvDns, $srvDom, (Opt 66 'Boot Server Host Name' "tftp.$dom" $false)) @() @() (Dyn @(Range '10.40.0.20' '10.40.0.200') @('SEP') 60 0 0) $null

    # 6 - Lab: inactive scope
    $s6 = Scope '172.16.50.0' 'Lab' 'Test lab (disabled)' $false '255.255.255.0' '172.16.50.10' '172.16.50.200' '1 d' 0 0 '' `
        @((Opt 3 'Router' '172.16.50.1' $false), $srvDns, $srvDom) @() @() @() $null

    # Policies, classes, option definitions, superscopes
    $s1.policies = @(Pol 'Kiosk-ShortLease' 1 'UserClass EQ Kiosk' '' @(, @(15, 'DNS Domain Name', "kiosk.$dom")) '4 h')
    $s5.policies = @((Pol 'Cisco-Phones' 1 'VendorClass EQ Cisco IP Phone' '10.40.0.20-10.40.0.120' @(, @(150, 'TFTP Server (Cisco)', '10.40.0.5'))),
                     (Pol 'Avaya-Phones' 2 'VendorClass EQ Avaya IP Phone' '10.40.0.121-10.40.0.200' @(, @(242, 'Avaya IP Phone', 'MCIPADD=10.40.0.6,HTTPSRVR=10.40.0.6')) '' $false))
    $classes = @(
        [pscustomobject]@{ name = 'Default BOOTP Class';                  type = 'User';   data = 'BOOTP.Microsoft';      desc = 'User class for BOOTP clients' },
        [pscustomobject]@{ name = 'Default Routing and Remote Access Class'; type = 'User'; data = 'RRAS.Microsoft';      desc = 'User class for remote access clients' },
        [pscustomobject]@{ name = 'Kiosk';                                type = 'User';   data = 'Kiosk';                desc = 'Lobby kiosks' },
        [pscustomobject]@{ name = 'Avaya IP Phone';                       type = 'Vendor'; data = 'ccp.avaya.com';        desc = '' },
        [pscustomobject]@{ name = 'Cisco IP Phone';                       type = 'Vendor'; data = 'Cisco Systems, Inc. IP Phone'; desc = '' },
        [pscustomobject]@{ name = 'Microsoft Windows 2000 Options';       type = 'Vendor'; data = 'MSFT 5.0';             desc = 'Microsoft vendor-specific options for Windows 2000 and above' })
    $optDefs = @(foreach ($d in @(@(3, 'Router', 'IPv4Address', $true), @(6, 'DNS Servers', 'IPv4Address', $true), @(15, 'DNS Domain Name', 'String', $false),
                                   @(42, 'NTP Servers', 'IPv4Address', $true), @(66, 'Boot Server Host Name', 'String', $false), @(67, 'Bootfile Name', 'String', $false),
                                   @(150, 'TFTP Server (Cisco)', 'IPv4Address', $true), @(242, 'Avaya IP Phone', 'String', $false))) {
        [pscustomobject]@{ id = $d[0]; name = $d[1]; type = $d[2]; vendor = ''; multi = $d[3]; def = ''; desc = '' } })
    $supers = @([pscustomobject]@{ name = 'HQ-Campus'; scopes = @('10.10.0.0', '10.10.8.0') })

    # Logs: last 7 days
    $since = $now.Date.AddDays(-6)
    $at = { param($d, $h) $since.AddDays($d).AddHours($h).AddMinutes($rnd.Next(60)).ToString('yyyy-MM-dd HH:mm:ss') }
    $days = foreach ($d in 0..6) {
        $wk = $since.AddDays($d).DayOfWeek -in 'Saturday', 'Sunday'
        [pscustomobject]@{ day = $since.AddDays($d).ToString('yyyy-MM-dd')
            new = $(if ($wk) { $rnd.Next(3, 12) } else { $rnd.Next(40, 90) }); renew = $(if ($wk) { $rnd.Next(150, 300) } else { $rnd.Next(900, 1400) })
            release = $rnd.Next(5, 35); conflict = $(if ($d -in 2, 5) { 1 } else { 0 }); full = $(if ($d -eq 5) { 3 } elseif ($d -eq 6) { 9 } else { 0 })
            denied = 0; dnsfail = $(if ($d -eq 4) { 4 } else { 0 }) }
    }
    $badL = @($s1.leases | Where-Object { $_.host -eq 'BAD_ADDRESS' })
    $rows = @()
    $rows += [pscustomobject]@{ time = (& $at 2 10); id = 13; desc = 'Conflict'; ip = $badL[0].ip; host = ''; mac = '' }
    $rows += [pscustomobject]@{ time = (& $at 5 9);  id = 13; desc = 'Conflict'; ip = $badL[1].ip; host = ''; mac = '' }
    foreach ($i in 1..12) { $rows += [pscustomobject]@{ time = $(if ($i -le 3) { & $at 5 (14 + $i) } else { & $at 6 (7 + $i % 4) }); id = 14; desc = 'Scope Full'; ip = '10.20.0.0'; host = ''; mac = '' } }
    foreach ($i in 1..4) { $l = $s1.leases[$rnd.Next(400)]; $rows += [pscustomobject]@{ time = (& $at 4 (9 + $i)); id = 31; desc = 'DNS Update Failed'; ip = $l.ip; host = $l.host; mac = $l.mac } }
    $logs = [pscustomobject]@{ eventsErr = ''; auditErr = ''; days = @($days); rows = @($rows | Sort-Object time -Descending)
        events = @(
            [pscustomobject]@{ log = 'System'; id = 1020; level = 3; count = 12; first = (& $at 5 8).Substring(0, 16); last = (& $at 6 16).Substring(0, 16)
                msg = 'Scope, 10.20.0.0, is 97 percent full with only 6 IP addresses remaining.' },
            [pscustomobject]@{ log = 'System'; id = 1056; level = 3; count = 7; first = (& $at 0 7).Substring(0, 16); last = (& $at 6 7).Substring(0, 16)
                msg = 'The DHCP service has detected that it is running on a DC and has no credentials configured for use with Dynamic DNS registrations initiated by the DHCP service. This is not a recommended security configuration.' }) }

    [pscustomobject]@{
        server = "DHCP01.$dom"; generated = $now.ToString('yyyy-MM-dd HH:mm'); scanned = $true; demo = $true; light = $false
        settings = [pscustomobject]@{ authorized = $true; conflict = 0; auditOn = $true; auditPath = 'C:\Windows\system32\dhcp'
            backupPath = 'C:\Windows\system32\dhcp\backup'; backupInt = '60'; dnsDyn = 'OnClientRequest'; dnsDel = $true; nameProt = $false; dnsCred = ''
            service = 'Running'; startType = 'Automatic'; version = '10.0'; allowOn = $false; denyOn = $true; allowN = 0; denyN = 3 }
        serverOptions = @(
            [pscustomobject]@{ id = 6;  name = 'DNS Servers';     value = '10.10.0.10, 10.10.0.11' },
            [pscustomobject]@{ id = 15; name = 'DNS Domain Name'; value = $dom },
            [pscustomobject]@{ id = 42; name = 'NTP Servers';     value = '10.10.0.10' })
        failover = @([pscustomobject]@{ name = 'dhcp01-dhcp02'; partner = "DHCP02.$dom"; mode = 'LoadBalance'; state = 'Normal'; role = ''
            mclt = '1 h'; lb = '50'; reserve = ''; auto = $false; switchInt = ''; scopes = @('10.10.0.0', '10.10.8.0', '10.30.0.0', '10.40.0.0') })
        policies = @(Pol 'Deny-Unknown-Vendors' 1 'VendorClass NE Microsoft Windows 2000 Options' '' @() '1 h' $false)
        classes = $classes; optionDefs = $optDefs; superscopes = $supers
        scopes = @($s1, $s2, $s3, $s4, $s5, $s6)
        logs = $logs
    }
}

# =============================================================================
#  EMBEDDED IMAGES (PNG, base64 - sources and full-size versions in docs/logo)
# =============================================================================
$IconPng = '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'     # 64x64 app icon: browser favicon, dashboard header, window icon
$LogoPng = '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'    # 128x128 transparent logo: launcher window

# Demo pair for Compare: the old server (DHCP01) and a new one (DHCP03) with deliberate migration mistakes
function New-DemoCompareData {
    $a = New-DemoData; $b = New-DemoData                           # two independent copies of the same sample server
    foreach ($x in $a, $b) { $x.logs = $null; $x.scanned = $false; $x.light = $true; foreach ($s in $x.scopes) { $s.leases = @(); $s.scan = $null } }
    $b.server = 'DHCP03.contoso.local'
    $b.settings.dnsCred = 'CONTOSO\svc-dhcp-dns'; $b.settings.denyN = 2
    $b.failover = @(); foreach ($s in $b.scopes) { $s.failover = ''; $s.inUse = [int]($s.inUse * 0.15) }   # failover not re-created yet, few leases so far
    $b.classes     = @($b.classes | Where-Object { $_.name -ne 'Kiosk' })
    $b.optionDefs  = @($b.optionDefs | Where-Object { $_.id -ne 242 })
    $b.superscopes = @([pscustomobject]@{ name = 'HQ-Campus'; scopes = @('10.10.0.0') })
    $sc = @{}; foreach ($s in $b.scopes) { $sc[$s.id] = $s }
    $p = $sc['10.10.8.0']; $p.reservations = @($p.reservations | Select-Object -Skip 1); $p.reservations[3].mac = '00-15-5d-0a-08-0e'
    $p.exclusions = @([pscustomobject]@{ start = '10.10.8.138'; end = '10.10.8.190'; count = 53 })
    $g = $sc['10.30.0.0']; $g.options = @($g.options | ForEach-Object { if ($_.id -eq 6) { [pscustomobject]@{ id = 6; name = 'DNS Servers'; value = '1.1.1.1, 9.9.9.9'; inherited = $false } } else { $_ } })
    $v = $sc['10.40.0.0']; $v.lease = '6 d'; $v.policies = @($v.policies[0])
    $sc['10.20.0.0'].active = $false
    $b.scopes = @($b.scopes | Where-Object { $_.id -ne '172.16.50.0' }) + [pscustomobject]@{ id = '10.50.0.0'; name = 'New-Wing'; desc = 'New building, first floor'; active = $true
        mask = '255.255.255.0'; start = '10.50.0.10'; end = '10.50.0.240'; lease = '8 d'; inUse = 0; free = 231; failover = ''; options = @(); exclusions = @()
        reservations = @(); leases = @(); policies = @(); scan = $null }
    $a, $b
}

# =============================================================================
#  DASHBOARD BUILDING BLOCKS shared by the analyze and compare dashboards
# =============================================================================
$Css = @'
:root{--bg:#f4f5f7;--card:#fff;--tx:#1f2328;--mut:#6b7280;--bd:#e5e7eb;--hd:#f0f2f5;--ok:#16a34a;--warn:#d97706;--crit:#dc2626;--info:#2563eb;--acc:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1b1f24;--tx:#e6e8eb;--mut:#9aa3ad;--bd:#2c323a;--hd:#232830}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 'Segoe UI',system-ui,Arial,sans-serif;background:var(--bg);color:var(--tx)}
.top{position:sticky;top:0;z-index:10;background:var(--card);border-bottom:1px solid var(--bd);padding:10px 24px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.top h1{font-size:18px;margin:0;flex:1 1 auto;white-space:nowrap}
.top h1 .logo{width:30px;height:30px;vertical-align:-8px;margin-right:9px}
.top h1 .by{font-size:12px;font-style:italic;font-weight:400;color:var(--acc);margin-left:6px}
.top h1 small{color:var(--mut);font-weight:400;font-size:13px;margin-left:10px}
.top h1 .demo{background:var(--warn);color:#fff;font-size:11px;font-weight:600;border-radius:4px;padding:2px 7px;margin-left:10px;vertical-align:2px}
.top input{padding:7px 10px;border:1px solid var(--bd);border-radius:6px;width:300px;max-width:100%;background:var(--bg);color:var(--tx);font:inherit}
button{cursor:pointer;border:1px solid var(--bd);background:var(--card);color:var(--tx);border-radius:6px;padding:5px 11px;font:inherit;font-size:13px}
button:hover{border-color:var(--acc)}
main{padding:20px 24px;max-width:1600px;margin:0 auto}
.kpi{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:18px}
.k{background:var(--card);border-radius:10px;padding:12px 16px;border-left:5px solid var(--ok);box-shadow:0 1px 2px #0001;cursor:pointer;transition:transform .1s}
.k:hover{transform:translateY(-2px)}
.k span{display:block;color:var(--mut);font-size:12px}.k b{font-size:21px;display:block;white-space:nowrap}.k b.sm{font-size:14px;margin-top:4px;white-space:normal}
.k.warn{border-color:var(--warn)}.k.crit{border-color:var(--crit)}.k.info{border-color:var(--info)}
.sec{background:var(--card);border-radius:10px;margin-bottom:14px;box-shadow:0 1px 2px #0001;scroll-margin-top:70px}
.sec>h2{margin:0;font-size:16px;padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:10px;user-select:none}
.sec>h2:before{content:'\25B8';color:var(--mut);transition:transform .15s;display:inline-block}
.sec.open>h2:before{transform:rotate(90deg)}
.sec>.body{display:none;padding:0 18px 18px}.sec.open>.body{display:block}
h3{font-size:12px;margin:20px 0 8px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.badge{font-size:12px;border-radius:10px;padding:1px 8px;background:var(--hd);color:var(--mut);font-weight:600}
.badge.crit{background:var(--crit);color:#fff}.badge.warn{background:var(--warn);color:#fff}.badge.ok{background:var(--ok);color:#fff}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.chips button.on{background:var(--acc);border-color:var(--acc);color:#fff}.chips button.on .badge{background:#fff3;color:#fff}
.iss{display:flex;gap:10px;align-items:center;padding:8px 12px;border-radius:6px;border-left:4px solid var(--mut);background:var(--hd);margin:5px 0}
.iss.crit{border-color:var(--crit)}.iss.warn{border-color:var(--warn)}.iss.info{border-color:var(--info)}.iss.ok{border-color:var(--ok)}
.iss.lnk{cursor:pointer}.iss.lnk:hover{filter:brightness(.97)}.iss>.pill{min-width:68px;text-align:center}.iss .go{margin-left:auto;color:var(--acc);font-size:12px;white-space:nowrap}
.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;white-space:nowrap;background:var(--hd);color:var(--mut)}
.pill.ok{background:#16a34a22;color:var(--ok)}.pill.warn{background:#d9770622;color:var(--warn)}.pill.crit{background:#dc262622;color:var(--crit)}.pill.info{background:#2563eb22;color:var(--info)}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;background:var(--hd);padding:8px 10px;white-space:nowrap;font-weight:600;font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--mut);position:sticky;top:0}
td{padding:8px 10px;border-top:1px solid var(--bd);vertical-align:top;font-variant-numeric:tabular-nums}
.g tbody tr:hover td,.wrap tbody tr:hover td{background:var(--hd)}
td.num,th.num{text-align:right}
.g th{cursor:pointer}.g th:hover{color:var(--acc)}
.tw{max-height:430px;overflow:auto;border:1px solid var(--bd);border-radius:6px}
.flt{padding:6px 10px;border:1px solid var(--bd);border-radius:6px;margin-bottom:8px;width:260px;background:var(--bg);color:var(--tx);font:inherit}
.mut{color:var(--mut);font-size:12px}.hint{margin-top:8px}
tr.sc{cursor:pointer;scroll-margin-top:70px}tr.sc:hover td,tr.sc.exp td{background:var(--hd)}
tr.sc.off td{opacity:.55}tr.sc.flash td{background:#2563eb22}
tr.det>td{padding:0;border-top:none}
.detail{padding:12px 16px 16px;border-left:4px solid var(--acc);background:var(--bg)}
.tabs{display:flex;gap:4px;margin-bottom:12px;border-bottom:1px solid var(--bd)}
.tabs button{border:none;border-bottom:2px solid transparent;border-radius:0;background:none;padding:7px 12px}
.tabs button.on{border-bottom-color:var(--acc);color:var(--acc);font-weight:600}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--ok)}
.dot.warn{background:var(--warn)}.dot.crit{background:var(--crit)}.dot.info{background:var(--info)}
.bar{height:8px;background:var(--hd);border-radius:4px;width:140px;overflow:hidden;margin-top:4px}.bar i{display:block;height:100%}
.bar i.ok{background:var(--ok)}.bar i.warn{background:var(--warn)}.bar i.crit{background:var(--crit)}
.tok{color:var(--ok)}.twarn{color:var(--warn)}.tcrit{color:var(--crit);font-weight:600}
.kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:8px}
.kv div{background:var(--card);border:1px solid var(--bd);border-radius:6px;padding:7px 11px}
.kv span{display:block;color:var(--mut);font-size:12px}.kv b{font-weight:600;word-break:break-word}
a[data-scope]{color:var(--acc);cursor:pointer;text-decoration:underline}
.map{display:grid;grid-template-columns:repeat(auto-fill,minmax(76px,1fr));gap:5px}
.t{border-radius:6px;padding:5px 4px;text-align:center;color:#fff;cursor:default;min-height:38px}.t:hover{outline:2px solid var(--tx)}
.t b{display:block;font-size:14px}.t span{font-size:10px;display:block;overflow:hidden;white-space:nowrap;text-overflow:ellipsis}
.occ{background:var(--crit)}.chk{background:var(--warn)}.free{background:var(--ok)}
.leg{display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin:4px 0 10px;font-size:13px}
.leg i{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:5px;vertical-align:-1px}
footer{color:var(--mut);font-size:12px;text-align:center;padding:10px 0 30px}
@media print{.top input,.top button{display:none}.sec>.body{display:block!important}.tw{max-height:none}}
#old{font:15px/1.5 'Segoe UI',Arial,sans-serif;max-width:720px;margin:60px auto;padding:24px 28px;border-left:6px solid #d97706;background:#fff;color:#1f2328}
'@
$JsCommon = @'
const $=s=>document.querySelector(s);
const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const arr=v=>Array.isArray(v)?v:(v==null?[]:[v]);
const ipN=ip=>String(ip).split('.').reduce((a,o)=>a*256+(+o||0),0);
const pctCls=p=>p>=CRIT?'crit':p>=WARN?'warn':'ok';
const pad=n=>String(n).padStart(3,'0');
const maskLen=m=>String(m).split('.').reduce((a,o)=>a+((+o).toString(2).match(/1/g)||[]).length,0);
const kv=(k,v)=>`<div><span>${k}</span><b>${v}</b></div>`;
const badge=(n,c)=>`<span class="badge ${c||''}">${n}</span>`;
const SEV={crit:0,warn:1,info:2}, SEVL={crit:'Critical',warn:'Warning',info:'Info'};
const STATE=[['ActiveReservation','Active reservation','ok'],['InactiveReservation','Inactive reservation','mut'],['Declined','Conflict','crit'],['Expired','Expired','warn'],['Offered','Offered','info'],['Active','Active','ok']];
const stInfo=s=>STATE.find(x=>String(s).includes(x[0]))||[s,s||'-','mut'];
const pill=s=>{const x=stInfo(s);return `<span class="pill ${x[2]}">${esc(x[1])}</span>`};
const plural=(n,w)=>`${n} ${w}${n===1?'':'s'}`;
const fmt=n=>Number(n||0).toLocaleString('en-US');
const z=n=>n?fmt(n):'<span class="mut">0</span>';
const num=v=>{const n=Number(v);return Number.isFinite(n)?n:0};
function sec(id,title,b,body,open){return `<section class="sec${open?' open':''}" id="${id}"><h2>${title} ${b||''}</h2><div class="body">${body}</div></section>`}
function chips(id,items){return `<div class="chips" data-for="${id}">${items.map((it,i)=>`<button data-f="${it[0]}" class="${i?'':'on'}">${it[1]} ${badge(it[2])}</button>`).join('')}</div>`}
/* policies: normalised once, shown in the analyze and compare dashboards */
const normPol=p=>{p.order=num(p.order);p.options=arr(p.options).filter(o=>o&&o.id!=null);p.options.forEach(o=>o.id=num(o.id));
  p.en=p.enabled?'Yes':'No';p.opts=p.options.map(o=>pad(o.id)+' '+o.name+': '+o.value).join('; ')};
const POLCOLS=[{k:'order',t:'Order',sv:r=>r.order,num:1},{k:'name',t:'Policy'},{k:'en',t:'Enabled'},{k:'conditions',t:'Conditions'},{k:'ranges',t:'IP ranges'},{k:'opts',t:'Options'},{k:'lease',t:'Lease'}];
function makeGrid(host,cols,rows,o={}){
  const search=o.search!==false; let sk=null,sd=1,q='';
  host.innerHTML=(search?'<input class="flt" type="search" placeholder="Filter...">':'')+'<div class="tw g"><table><thead></thead><tbody></tbody></table></div><div class="mut hint"></div>';
  const th=host.querySelector('thead'),tb=host.querySelector('tbody'),cnt=host.querySelector('.hint');
  const val=(r,c)=>c.sv?c.sv(r):String(r[c.k]??'').toLowerCase();
  function draw(){
    th.innerHTML='<tr>'+cols.map((c,i)=>`<th data-i="${i}" class="${c.num?'num':''}">${c.t}${sk===i?(sd>0?' &#9650;':' &#9660;'):''}</th>`).join('')+'</tr>';
    let R=rows; if(q){const Q=q.toLowerCase();R=R.filter(r=>cols.some(c=>String(r[c.k]??'').toLowerCase().includes(Q)))}
    if(sk!==null){const c=cols[sk];R=[...R].sort((a,b)=>{const x=val(a,c),y=val(b,c);return(x>y?1:x<y?-1:0)*sd})}
    tb.innerHTML=R.length?R.map(r=>'<tr>'+cols.map(c=>`<td class="${c.num?'num':''}">${c.f?c.f(r):esc(r[c.k])}</td>`).join('')+'</tr>').join(''):`<tr><td colspan="${cols.length}" class="mut">${o.empty||'No data'}</td></tr>`;
    cnt.textContent=R.length===rows.length?plural(rows.length,'item'):`${R.length} of ${plural(rows.length,'item')}`;
  }
  th.onclick=e=>{const t=e.target.closest('th');if(!t)return;const i=+t.dataset.i;if(sk===i)sd=-sd;else{sk=i;sd=1}draw()};
  if(search)host.querySelector('.flt').oninput=e=>{q=e.target.value;draw()};
  draw();
}
'@
# =============================================================================
#  HTML DASHBOARD TEMPLATE (data is injected in place of __DATA__, the icon in place of __ICON__)
# =============================================================================
$Template = @'
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-__SCRIPT_HASH__'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>DHCP Analyzer by Starkark98</title>
<link rel="icon" type="image/png" href="data:image/png;base64,__ICON__">
<style>
__CSS__
</style></head><body>
<div id="old"><b style="font-size:18px">DHCP Analyzer by Starkark98</b><br><br>
This dashboard requires a modern browser: <b>Microsoft Edge</b>, <b>Google Chrome</b> or <b>Firefox</b>.<br>
Internet Explorer is not supported. Copy this file to a PC with Edge or Chrome and open it there.</div>
<div class="top">
  <h1><img class="logo" src="data:image/png;base64,__ICON__" alt="">DHCP Analyzer<span class="by">by Starkark98</span><small id="sub"></small><span id="demo"></span></h1>
  <input id="q" type="search" placeholder="Search IP, hostname, MAC or scope...  ( / )">
  <button id="bx">Expand all</button><button id="bc">Collapse all</button>
</div>
<main id="m"></main>
<footer id="ft"></footer>
<script>
document.getElementById('old').remove();
const D=__DATA__, WARN=80, CRIT=95;
__JSCOMMON__
const wday=d=>{const x=new Date(d+'T00:00:00');return isNaN(x)?'':x.toLocaleDateString('en-US',{weekday:'short'})};

/* ---------- data normalization ---------- */
/* every value from the server is untrusted: text goes through esc(), numbers are forced with num() */
D.scopes=arr(D.scopes); D.failover=arr(D.failover); D.serverOptions=arr(D.serverOptions);
D.serverOptions.forEach(o=>o.id=num(o.id));
const LG=D.logs||null; if(LG){['events','days','rows'].forEach(k=>LG[k]=arr(LG[k]));
  LG.events.forEach(e=>{e.level=num(e.level);e.id=num(e.id);e.count=num(e.count)}); LG.rows.forEach(r=>r.id=num(r.id))}
D.failover.forEach(f=>f.scopes=arr(f.scopes));
['policies','classes','optionDefs','superscopes'].forEach(k=>D[k]=arr(D[k]));
D.policies.forEach(normPol); D.optionDefs.forEach(o=>o.id=num(o.id)); D.superscopes.forEach(x=>x.scopes=arr(x.scopes));
D.scopes.forEach(s=>{
  ['options','exclusions','reservations','leases','policies'].forEach(k=>s[k]=arr(s[k]));
  s.policies.forEach(normPol); const sup=D.superscopes.find(x=>x.scopes.includes(s.id)); s.super=sup?sup.name:'';
  s.inUse=num(s.inUse); s.free=num(s.free); s.options.forEach(o=>o.id=num(o.id)); s.exclusions.forEach(e=>e.count=num(e.count));
  if(s.scan){s.scan.ips=arr(s.scan.ips); s.scan.ips.forEach(x=>{if(!['occ','chk','free'].includes(x.cls))x.cls='chk'})}
  s.pool=s.inUse+s.free; s.pct=s.pool?Math.round(s.inUse*1000/s.pool)/10:0;
  s.cnt={act:0,exp:0,bad:0,rina:0};
  s.leases.forEach(l=>{const st=String(l.state);
    if(st==='Active'||st==='ActiveReservation')s.cnt.act++;
    if(st.includes('Expired'))s.cnt.exp++;
    if(st.includes('Declined')||l.host==='BAD_ADDRESS')s.cnt.bad++;
    if(st==='InactiveReservation')s.cnt.rina++;});
  s.exN=s.exclusions.reduce((a,e)=>a+e.count,0);
  const o=id=>s.options.find(x=>x.id===id); s.gw=o(3); s.dns=o(6); s.dom=o(15);
});

/* ---------- issues ---------- */
const I=[]; const add=(sev,text,scope,go)=>I.push({sev,text,scope,go});
const scopeOf=ip=>{ip=String(ip||'').trim();if(!/^\d+\.\d+\.\d+\.\d+$/.test(ip))return null;const a=ipN(ip);return D.scopes.find(s=>((a&ipN(s.mask))>>>0)===ipN(s.id))||null};
const sLbl=s=>`Scope <b>${esc(s.id)}</b>${s.name?' ('+esc(s.name)+')':''}`;
const S=D.settings||{}; ['allowN','denyN','conflict'].forEach(k=>{if(S[k]!=null)S[k]=num(S[k])});
if(S.authorized===false)add('crit','Server is not authorized in Active Directory');
if(!D.failover.length)add('warn','No failover configured: the DHCP server is a single point of failure');
D.failover.forEach(f=>{if(f.state!=='Normal')add('crit',`Failover <b>${esc(f.name)}</b> is in state ${esc(f.state)}`)});
if(S.auditOn===false)add('warn','DHCP audit log is disabled');
if(S.dnsDyn&&S.dnsDyn!=='Never'&&!S.dnsCred)add('warn','Dynamic DNS updates are enabled without dedicated DNS credentials (not recommended, especially when DHCP runs on a domain controller)');
D.scopes.forEach(s=>{
  const L=sLbl(s);
  if(!s.active){add('info',L+' is inactive',s.id);return}
  if(s.pct>=CRIT)add('crit',`${L} is ${s.pct}% full (${s.free} free)`,s.id);
  else if(s.pct>=WARN)add('warn',`${L} is ${s.pct}% full (${s.free} free)`,s.id);
  if(s.cnt.bad)add('warn',`${L}: ${plural(s.cnt.bad,'IP')} marked BAD_ADDRESS (IP conflicts)`,s.id);
  if(!s.gw)add('warn',`${L}: no gateway (option 003)`,s.id);
  if(!s.dns)add('warn',`${L}: no DNS servers (option 006)`,s.id);
  if(D.failover.length&&!s.failover)add('warn',`${L} is not part of any failover relationship`,s.id);
  if(s.cnt.rina)add('info',`${L}: ${plural(s.cnt.rina,'reservation')} without an active lease (device off or retired?)`,s.id);
  if(s.scan&&!s.scan.skipped){const f=s.scan.ips.filter(x=>x.cls==='free').length;
    if(f)add('info',`${L}: ${plural(f,'excluded IP')} with no evidence of use (potentially reclaimable)`,s.id)}
});
if(S.service&&S.service!=='Running')add('crit',`DHCP Server service is ${esc(S.service)}`,null,'config');
if(S.allowOn)add('info',`MAC allow list is enabled: only ${plural(S.allowN||0,'listed client')} can get an address`,null,'config');
const lt={new:0,renew:0,release:0,conflict:0,full:0,denied:0,dnsfail:0};let evErr=0,evCrit=0;
if(LG){
  LG.days.forEach(d=>Object.keys(lt).forEach(k=>lt[k]+=+d[k]||0));
  LG.rows.forEach(r=>{const s=scopeOf(r.ip);r.scope=s?s.id:''});
  LG.events.forEach(e=>{if(e.level<=2)evErr+=e.count;if(e.level===1)evCrit+=e.count});
  if(lt.full){const by={};let mapped=0;LG.rows.filter(r=>r.id===14&&r.scope).forEach(r=>{by[r.scope]=(by[r.scope]||0)+1;mapped++});
    Object.keys(by).forEach(k=>{const t=`pool exhausted ${plural(by[k],'time')} in the last 7 days`,u=I.find(i=>i.scope===k&&i.text.includes(' full ('));
      if(u){u.sev='crit';u.text+=' &middot; '+t}else add('crit',`${sLbl(D.scopes.find(x=>x.id===k))}: address ${t}`,k)});
    if(lt.full>mapped)add('crit',`Address pool exhausted ${plural(lt.full-mapped,'time')} in the last 7 days (audit log)`,null,'logs')}
  const badIps=new Set();D.scopes.forEach(s=>s.leases.forEach(l=>{if(String(l.state).includes('Declined')||l.host==='BAD_ADDRESS')badIps.add(l.ip)}));
  const cNew=lt.conflict-LG.rows.filter(r=>r.id===13&&badIps.has(r.ip)).length;
  if(cNew>0)add('warn',`${plural(cNew,'IP conflict')} detected on the network in the last 7 days (not currently marked BAD_ADDRESS)`,null,'logs');
  if(lt.denied)add('warn',`${plural(lt.denied,'lease request')} denied in the last 7 days: check MAC filters and policies`,null,'logs');
  if(lt.dnsfail)add('warn',`${plural(lt.dnsfail,'dynamic DNS update')} failed in the last 7 days`,null,'logs');
  if(evErr)add(evCrit?'crit':'warn',`${plural(evErr,'error event')} in the DHCP event logs in the last 7 days`,null,'logs');
  if(LG.eventsErr)add('info','Event logs could not be read: '+esc(LG.eventsErr),null,'logs');
  if(LG.auditErr&&S.auditOn!==false)add('info','Audit log files could not be read: '+esc(LG.auditErr),null,'logs');
}
D.scopes.forEach(s=>{const m=I.filter(i=>i.scope===s.id).sort((a,b)=>SEV[a.sev]-SEV[b.sev])[0]; s.sev=m?m.sev:'ok'});
const logProb=lt.full+lt.conflict+lt.denied+lt.dnsfail+evErr;
const nC=I.filter(i=>i.sev==='crit').length,nW=I.filter(i=>i.sev==='warn').length,nI=I.filter(i=>i.sev==='info').length;

/* ---------- components ---------- */
const optTxt=o=>o?esc(o.value)+(o.inherited?' <span class="mut" title="Inherited from server options">(srv)</span>':''):'<span class="tcrit">missing</span>';

function mapHtml(sc,wide){
  if(sc.skipped)return '<div class="mut">Exclusion too large (over 1024 IPs): scan skipped.</div>';
  const c={occ:0,chk:0,free:0}; sc.ips.forEach(x=>c[x.cls]++);
  const tiles=sc.ips.map(x=>{const tip=[x.ip,x.ping!==''&&x.ping!=null?'Ping: '+x.ping+' ms':'',x.tcp?'TCP: '+x.tcp:'',x.mac?'MAC: '+x.mac:'',x.dns?'DNS: '+x.dns:'',x.resv?'Reservation: '+x.resv:''].filter(Boolean).join('\n');
    const nm=x.resv||String(x.dns||'').split('.')[0];
    return `<div class="t ${x.cls}" title="${esc(tip)}"><b>.${esc(String(x.ip).split('.').slice(wide?2:3).join('.'))}</b><span>${esc(nm)}</span></div>`}).join('');
  const bl=[];let st=null,la=null;
  sc.ips.forEach(x=>{const n=ipN(x.ip);if(x.cls==='free'&&st!==null&&n===la+1){la=n;return}
    if(st!==null){bl.push([st,la]);st=null}if(x.cls==='free'){st=n;la=n}});
  if(st!==null)bl.push([st,la]);
  const ip=n=>[n>>>24,(n>>>16)&255,(n>>>8)&255,n&255].join('.');
  bl.sort((a,b)=>(b[1]-b[0])-(a[1]-a[0]));
  return `<div class="leg"><span><i class="occ"></i>In use ${c.occ}</span><span><i class="chk"></i>To verify ${c.chk}</span><span><i class="free"></i>Free ${c.free}</span>
    <span class="mut">${sc.arp?'ARP check active':'ARP not available (this PC is not on this subnet): ping, ports and DNS only'} &middot; hover a tile for details</span></div>
    <div class="map">${tiles}</div>
    <h3>Contiguous free blocks</h3>${bl.length?`<div class="kv">${bl.map(b=>kv(ip(b[0])+' &ndash; '+ip(b[1]),plural(b[1]-b[0]+1,'IP'))).join('')}</div>`:'<div class="mut">No free blocks</div>'}
    <div class="mut hint">Free = no evidence of use, not a guarantee: double-check before shrinking the exclusion.</div>`;
}

/* ---------- scopes ---------- */
function renderScopes(f){
  const L=D.scopes.filter(s=>f==='all'||(f==='att'&&(s.sev==='crit'||s.sev==='warn'))||(f==='off'&&!s.active));
  $('#sct').innerHTML=L.map(s=>{const c=pctCls(s.pct);return `<tr class="sc${s.active?'':' off'}" data-id="${esc(s.id)}">
    <td><span class="dot ${s.sev}" title="${s.sev==='ok'?'No issues':SEVL[s.sev]}"></span></td>
    <td><b>${esc(s.id)}</b>${s.active?'':' <span class="pill">inactive</span>'}<div class="mut">${esc(s.name)}</div></td>
    <td>${esc(s.start)} &ndash; ${esc(s.end)}<div class="mut">/${maskLen(s.mask)} &middot; lease ${esc(s.lease)}</div></td>
    <td><div class="bar"><i class="${c}" style="width:${Math.min(s.pct,100)}%"></i></div><div class="mut">${s.inUse} / ${s.pool} &middot; <b class="t${c}">${s.pct}%</b></div></td>
    <td class="num">${s.free}</td>
    <td class="num">${z(s.reservations.length)}${s.cnt.rina?`<div class="mut">${s.cnt.rina} inactive</div>`:''}</td>
    <td class="num">${z(s.exN)}</td>
    <td class="num ${s.cnt.bad?'tcrit':''}">${z(s.cnt.bad)}</td>
    <td>${optTxt(s.gw)}</td><td>${optTxt(s.dns)}</td>
    <td>${s.failover?esc(s.failover):'<span class="mut">&ndash;</span>'}</td></tr>`}).join('')||'<tr><td colspan="11" class="mut">No scopes</td></tr>';
}
function toggleScope(tr,tab){
  const nx=tr.nextElementSibling;
  if(nx&&nx.classList.contains('det')){nx.remove();tr.classList.remove('exp');if(!tab)return}
  const s=D.scopes.find(x=>x.id===tr.dataset.id);
  const d=document.createElement('tr');d.className='det';d.innerHTML='<td colspan="11"><div class="detail"></div></td>';
  tr.after(d);tr.classList.add('exp');buildDetail(d.querySelector('.detail'),s,tab||'ov');
}
function buildDetail(el,s,tab){
  const T=[['ov','Overview'],['lease',`Leases (${s.leases.length})`],['res',`Reservations (${s.reservations.length})`],['exc',`Exclusions (${s.exclusions.length})`],['pol',`Policies (${s.policies.length})`]];
  el.innerHTML=`<div class="tabs">${T.map(t=>`<button data-tab="${t[0]}">${t[1]}</button>`).join('')}</div><div class="tab"></div>`;
  el.querySelector('.tabs').onclick=e=>{const b=e.target.closest('button');if(b){e.stopPropagation();showTab(el,s,b.dataset.tab)}};
  showTab(el,s,tab);
}
function showTab(el,s,t){
  el.querySelectorAll('.tabs button').forEach(b=>b.classList.toggle('on',b.dataset.tab===t));
  const T=el.querySelector('.tab');
  if(t==='ov'){
    T.innerHTML=`<div class="kv">${kv('Range',esc(s.start)+' &ndash; '+esc(s.end))}${kv('Subnet mask',esc(s.mask)+' (/'+maskLen(s.mask)+')')}${kv('Lease duration',esc(s.lease))}${kv('Distributable pool',plural(s.pool,'IP')+' ('+s.free+' free)')}${kv('Failover',s.failover?esc(s.failover):'None')}${s.super?kv('Superscope',esc(s.super)):''}${s.desc?kv('Description',esc(s.desc)):''}</div>
      <h3>Options</h3>${s.options.length?`<div class="kv">${s.options.map(o=>kv(pad(o.id)+' '+esc(o.name)+(o.inherited?' <i>(from server)</i>':''),esc(o.value))).join('')}</div>`:'<div class="mut">No options</div>'}`;
  }else if(t==='lease'){
    const F=[['All',()=>true],['Active',l=>stInfo(l.state)[2]==='ok'],['Expired',l=>String(l.state).includes('Expired')],['Reservations',l=>String(l.state).includes('Reservation')],['Conflicts',l=>String(l.state).includes('Declined')||l.host==='BAD_ADDRESS']];
    T.innerHTML=`<div class="chips">${F.map((f,i)=>`<button data-i="${i}" class="${i?'':'on'}">${f[0]} ${badge(s.leases.filter(f[1]).length)}</button>`).join('')}</div><div class="gg"></div>`;
    const draw=i=>makeGrid(T.querySelector('.gg'),[{k:'ip',t:'IP',sv:r=>ipN(r.ip)},{k:'host',t:'Hostname'},{k:'mac',t:'MAC'},{k:'state',t:'State',f:r=>pill(r.state)},{k:'expiry',t:'Expires'}],s.leases.filter(F[i][1]),{empty:'No leases'});
    T.querySelector('.chips').onclick=e=>{const b=e.target.closest('button');if(!b)return;T.querySelectorAll('.chips button').forEach(x=>x.classList.toggle('on',x===b));draw(+b.dataset.i)};
    draw(0);
  }else if(t==='res'){
    const lm={};s.leases.forEach(l=>lm[l.ip]=l.state);
    makeGrid(T,[{k:'ip',t:'IP',sv:r=>ipN(r.ip)},{k:'name',t:'Name'},{k:'mac',t:'MAC'},{k:'type',t:'Type'},{k:'desc',t:'Description'},{k:'st',t:'State',f:r=>pill(r.st)}],
      s.reservations.map(r=>Object.assign({},r,{st:lm[r.ip]||'InactiveReservation'})),{empty:'No reservations'});
  }else if(t==='pol'){
    makeGrid(T,POLCOLS,s.policies,{empty:'No policies in this scope',search:false});
  }else{
    T.innerHTML=(s.exclusions.length?`<div class="kv">${s.exclusions.map(e=>kv(esc(e.start)+' &ndash; '+esc(e.end),plural(e.count,'IP'))).join('')}</div>`:'<div class="mut">No exclusions</div>')
      +(s.scan?'<h3>Real usage of excluded IPs</h3>'+mapHtml(s.scan,maskLen(s.mask)<24):(s.exclusions.length?`<div class="mut hint">${D.scanned?'Scan not performed (scope inactive).':'Exclusion scan was not requested.'}</div>`:''));
  }
}
function openScope(id,tab){
  $('#scope').classList.add('open');
  const find=()=>[...document.querySelectorAll('tr.sc')].find(r=>r.dataset.id===id);   /* no selector built from data */
  let tr=find();
  if(!tr){document.querySelectorAll('[data-for="scf"] button').forEach(b=>b.classList.toggle('on',b.dataset.f==='all'));renderScopes('all');tr=find()}
  if(!tr)return;
  toggleScope(tr,tab||'ov');tr.scrollIntoView({behavior:'smooth',block:'start'});
  tr.classList.add('flash');setTimeout(()=>tr.classList.remove('flash'),1500);
}

/* ---------- issues list ---------- */
function renderIssues(f){
  const L=I.filter(i=>f==='all'||i.sev===f).sort((a,b)=>SEV[a.sev]-SEV[b.sev]);
  $('#isl').innerHTML=L.length?L.map(i=>`<div class="iss ${i.sev}${i.scope?' lnk" data-scope="'+esc(i.scope)+'"':i.go?' lnk" data-go="'+i.go+'"':'"'}><span class="pill ${i.sev}">${SEVL[i.sev]}</span><span>${i.text}</span>${i.scope?'<span class="go">Open scope &rsaquo;</span>':i.go?'<span class="go">Open &rsaquo;</span>':''}</div>`).join('')
    :'<div class="iss ok"><span class="pill ok">OK</span><span>No issues found</span></div>';
}

/* ---------- global search ---------- */
function search(q){
  const R=$('#sres');q=q.trim().toLowerCase();if(q.length<2){R.innerHTML='';return}
  const qn=q.replace(/[-:.\s]/g,'');
  const m=v=>{const s=String(v??'').toLowerCase();return s.includes(q)||(qn.length>=4&&s.replace(/[-:.\s]/g,'').includes(qn))};
  const out=[];
  D.scopes.forEach(s=>{
    if(m(s.id)||m(s.name))out.push({t:'Scope',ip:s.id,n:s.name,mac:'',sc:s.id,st:'',tab:'ov'});
    s.leases.forEach(l=>{if(m(l.ip)||m(l.host)||m(l.mac))out.push({t:'Lease',ip:l.ip,n:l.host,mac:l.mac,sc:s.id,st:l.state,tab:'lease'})});
    s.reservations.forEach(r=>{if(m(r.ip)||m(r.name)||m(r.mac)||m(r.desc))out.push({t:'Reservation',ip:r.ip,n:r.name,mac:r.mac,sc:s.id,st:'',tab:'res'})});
    if(s.scan)s.scan.ips.forEach(x=>{if(x.cls!=='free'&&(m(x.ip)||m(x.dns)||m(x.mac)||m(x.resv)))out.push({t:'Excluded IP',ip:x.ip,n:x.dns||x.resv,mac:x.mac,sc:s.id,st:'',tab:'exc'})});
  });
  R.innerHTML=sec('sr','Search results',badge(out.length,out.length?'ok':''),'<div class="gg"></div>',true);
  makeGrid(R.querySelector('.gg'),[{k:'t',t:'Type'},{k:'ip',t:'IP',sv:r=>ipN(r.ip)},{k:'n',t:'Host / Name'},{k:'mac',t:'MAC'},{k:'sc',t:'Scope',sv:r=>ipN(r.sc)},{k:'st',t:'State',f:r=>r.st?pill(r.st):''},{k:'go',t:'',f:r=>`<button data-scope="${esc(r.sc)}" data-tab="${r.tab}">Open &rsaquo;</button>`}],
    out.slice(0,500),{search:false,empty:'No results'});
}

/* ---------- page ---------- */
const tot=D.scopes.filter(s=>s.active).reduce((a,s)=>{a.i+=s.inUse;a.p+=s.pool;a.l+=s.cnt.act;a.b+=s.cnt.bad;return a},{i:0,p:0,l:0,b:0});
const totPct=tot.p?Math.round(tot.i*1000/tot.p)/10:0;
const act=D.scopes.filter(s=>s.active).length;
const foCls=!D.failover.length?'warn':D.failover.some(f=>f.state!=='Normal')?'crit':'ok';
const foTxt=D.failover.length?D.failover.map(f=>`${esc(f.mode)} &middot; ${esc(f.state)}`).join('<br>'):'None';
const yn=(v,y,n)=>v==null?'n/a':(v?y:n);

$('#sub').innerHTML=`${esc(D.server)} &middot; ${esc(D.generated)}`;
if(D.demo)$('#demo').innerHTML='<span class="demo">DEMO DATA</span>';
$('#ft').innerHTML=`DHCP Analyzer by <b>Starkark98</b> &middot; ${esc(D.server)} &middot; generated ${esc(D.generated)} &middot; read-only report`;

const K=[
  ['Active scopes',`${act} / ${D.scopes.length}`,act<D.scopes.length?'info':'ok','scope'],
  ['Overall utilization',totPct+'%',pctCls(totPct),'scope'],
  ['In use / pool',`${fmt(tot.i)} / ${fmt(tot.p)}`,'ok','scope'],
  ['Log problems (7 days)',LG?logProb:'n/a',!LG?'info':(lt.full||evCrit)?'crit':logProb?'warn':'ok','logs'],
  ['IP conflicts',tot.b,tot.b?'warn':'ok','scope'],
  ['Failover',foTxt,foCls,'failover','sm'],
  ['Authorized in AD',yn(S.authorized,'Yes','NO'),S.authorized===false?'crit':'ok','config'],
  ['Issues',I.length,nC?'crit':nW?'warn':'ok','issues']
];
let h='<div class="kpi">'+K.map(k=>`<div class="k ${k[2]}" data-go="${k[3]}"><span>${k[0]}</span><b class="${k[4]||''}">${k[1]}</b></div>`).join('')+'</div><div id="sres"></div>';

h+=sec('issues','Issues',badge(I.length,nC?'crit':nW?'warn':'ok'),
  chips('isf',[['all','All',I.length],['crit','Critical',nC],['warn','Warnings',nW],['info','Info',nI]])+'<div id="isl"></div>',I.length>0);

const nAtt=D.scopes.filter(s=>s.sev==='crit'||s.sev==='warn').length,nOff=D.scopes.filter(s=>!s.active).length;
h+=sec('scope','Scopes',badge(D.scopes.length),
  chips('scf',[['all','All',D.scopes.length],['att','Needs attention',nAtt],['off','Inactive',nOff]])+
  `<div class="wrap"><table><thead><tr><th></th><th>Scope</th><th>Range</th><th>Utilization</th><th class="num">Free</th><th class="num">Reserv.</th><th class="num">Excluded IPs</th><th class="num">Conflicts</th><th>Gateway</th><th>DNS</th><th>Failover</th></tr></thead><tbody id="sct"></tbody></table></div>
  <div class="mut hint">Click a scope to see its leases, reservations, exclusions and options. (srv) = value inherited from server options.</div>`,true);

const AUD={13:['IP conflict','warn'],14:['Pool exhausted','crit'],15:['Lease denied','warn'],31:['DNS update failed','warn'],34:['DNS queue full','warn'],35:['DNS update failed','warn']};
const LVL={1:['Critical','crit'],2:['Error','crit'],3:['Warning','warn']};
function logsBody(){
  if(!LG)return '<div class="mut">Logs were not collected.</div>';
  const C=[['new','New leases'],['renew','Renewals'],['release','Releases'],['conflict','Conflicts','warn'],['full','Pool exhausted','crit'],['denied','Denied','warn'],['dnsfail','DNS failures','warn']];
  const td=(v,c,b)=>`<td class="num${c&&v?' t'+c:''}"${b?' style="font-weight:600"':''}>${v?fmt(v):'<span class="mut">0</span>'}</td>`;
  const audit=LG.auditErr?`<div class="mut">${S.auditOn===false?'Audit log is disabled on the server: enable it to get lease history.':'Audit log files could not be read: '+esc(LG.auditErr)}</div>`
    :`<div class="wrap"><table><thead><tr><th>Day</th>${C.map(c=>`<th class="num">${c[1]}</th>`).join('')}</tr></thead><tbody>${LG.days.map(d=>`<tr><td><span class="mut" style="display:inline-block;width:34px">${wday(d.day)}</span>${esc(d.day)}</td>${C.map(c=>td(+d[c[0]]||0,c[2])).join('')}</tr>`).join('')}<tr><td><b>Total</b></td>${C.map(c=>td(lt[c[0]],c[2],1)).join('')}</tr></tbody></table></div>
      <h3>Problem entries</h3><div id="lgr"></div>`;
  return `<h3>DHCP audit log &ndash; daily activity</h3>${audit}<h3>Event logs &ndash; critical, errors and warnings</h3>${LG.eventsErr?`<div class="mut">${LG.events.length?'Some event logs':'Event logs'} could not be read: ${esc(LG.eventsErr)}</div>`:''}${!LG.eventsErr||LG.events.length?'<div id="lge"></div>':''}`;
}
h+=sec('logs','Logs and events',`${badge(logProb,(lt.full||evCrit)?'crit':logProb?'warn':'ok')} <span class="mut">last 7 days</span>`,logsBody(),logProb>0);

h+=sec('failover','Failover',badge(D.failover.length||'none',foCls),
  D.failover.length?`<div class="wrap"><table><thead><tr><th>Relationship</th><th>Partner</th><th>Mode</th><th>Settings</th><th>State</th><th>MCLT</th><th>Auto switchover</th><th>Scopes</th></tr></thead><tbody>${D.failover.map(f=>`<tr>
    <td><b>${esc(f.name)}</b></td><td>${esc(f.partner)}</td><td>${esc(f.mode)}</td>
    <td>${f.mode==='LoadBalance'?'Load balance '+esc(f.lb)+'%':'Reserve '+esc(f.reserve)+'% &middot; role '+esc(f.role)}</td>
    <td><span class="pill ${f.state==='Normal'?'ok':'crit'}">${esc(f.state)}</span></td><td>${esc(f.mclt)}</td>
    <td>${f.auto?'Yes ('+esc(f.switchInt)+')':'No'}</td>
    <td>${f.scopes.map(x=>`<a data-scope="${esc(x)}">${esc(x)}</a>`).join(', ')}</td></tr>`).join('')}</tbody></table></div>`
  :'<div class="mut">No failover relationship configured.</div>',foCls!=='ok');

h+=sec('config','Server configuration','',
  `<div class="kv">${kv('DHCP Server service',S.service?(S.service==='Running'?'Running':'<span class="tcrit">'+esc(S.service)+'</span>')+(S.startType?' &middot; '+esc(S.startType):''):'n/a')}
  ${kv('DHCP server version',S.version?esc(S.version):'n/a')}
  ${kv('MAC filters','Allow list '+(S.allowOn?'<b class="twarn">enabled</b>':'disabled')+' ('+(S.allowN||0)+') &middot; Deny list '+(S.denyOn?'enabled':'disabled')+' ('+(S.denyN||0)+')')}
  ${kv('Conflict detection',S.conflict==null?'n/a':plural(S.conflict,'attempt'))}
  ${kv('Audit log',S.auditOn==null?'n/a':S.auditOn?'Enabled &middot; '+esc(S.auditPath):'<span class="twarn">Disabled</span>')}
  ${kv('Database backup',S.backupPath?esc(S.backupPath)+' &middot; every '+esc(S.backupInt)+' min':'n/a')}
  ${kv('Dynamic DNS updates',esc(S.dnsDyn)||'n/a')}
  ${kv('Delete DNS records on lease expiry',yn(S.dnsDel,'Yes','No'))}
  ${kv('Name protection',yn(S.nameProt,'Enabled','Disabled'))}
  ${kv('DNS update credentials',S.dnsCred?esc(S.dnsCred):'Not configured')}</div>
  <h3>Server options</h3>${D.serverOptions.length?`<div class="kv">${D.serverOptions.map(o=>kv(pad(o.id)+' '+esc(o.name),esc(o.value))).join('')}</div>`:'<div class="mut">No server-level options</div>'}
  <h3>Server-level policies</h3><div id="cfgPol"></div>
  <h3>User and vendor classes</h3><div id="cfgCls"></div>
  <h3>Option definitions</h3><div id="cfgDef"></div>
  <h3>Superscopes</h3><div id="cfgSup"></div>`,false);

$('#m').innerHTML=h;
renderIssues('all');renderScopes('all');
makeGrid($('#cfgPol'),POLCOLS.filter(c=>c.k!=='ranges'),D.policies,{empty:'No server-level policies',search:false});
makeGrid($('#cfgCls'),[{k:'type',t:'Type'},{k:'name',t:'Class'},{k:'data',t:'Data'},{k:'desc',t:'Description'}],D.classes,{empty:'No classes',search:false});
makeGrid($('#cfgDef'),[{k:'id',t:'Option',sv:r=>r.id,num:1},{k:'name',t:'Name'},{k:'type',t:'Type'},{k:'vendor',t:'Vendor class'},{k:'mv',t:'Multi-valued'},{k:'def',t:'Default'}],
  D.optionDefs.map(o=>Object.assign({},o,{mv:o.multi?'Yes':'No'})),{empty:'No option definitions'});
makeGrid($('#cfgSup'),[{k:'name',t:'Superscope'},{k:'sc',t:'Member scopes'}],D.superscopes.map(x=>({name:x.name,sc:x.scopes.join(', ')})),{empty:'No superscopes',search:false});
if(LG&&$('#lgr'))makeGrid($('#lgr'),[{k:'time',t:'Time'},{k:'id',t:'Event',sv:r=>r.id,f:r=>{const a=AUD[r.id]||[r.id,'mut'];return `<span class="pill ${a[1]}">${esc(a[0])}</span>`}},{k:'ip',t:'IP',sv:r=>ipN(r.ip)},
  {k:'scope',t:'Scope',sv:r=>ipN(r.scope),f:r=>r.scope?`<a data-scope="${esc(r.scope)}">${esc(r.scope)}</a>`:''},{k:'host',t:'Host'},{k:'mac',t:'MAC'},{k:'desc',t:'Description'}],LG.rows,{empty:'No problems in the last 7 days'});
if(LG&&$('#lge'))makeGrid($('#lge'),[{k:'level',t:'Level',sv:r=>r.level,f:r=>{const l=LVL[r.level]||['Info','mut'];return `<span class="pill ${l[1]}">${l[0]}</span>`}},{k:'log',t:'Log'},{k:'id',t:'Event ID',sv:r=>r.id,num:1},
  {k:'count',t:'Count',sv:r=>r.count,num:1},{k:'first',t:'First'},{k:'last',t:'Last'},{k:'msg',t:'Message'}],LG.events,{empty:'No errors or warnings in the last 7 days'});

/* ---------- interactions ---------- */
document.addEventListener('click',e=>{
  let t;
  if((t=e.target.closest('[data-scope]'))){openScope(t.dataset.scope,t.dataset.tab);return}
  if((t=e.target.closest('[data-go]'))){const s=document.getElementById(t.dataset.go);s.classList.add('open');s.scrollIntoView({behavior:'smooth',block:'start'});return}
  if((t=e.target.closest('.sec>h2'))){t.parentNode.classList.toggle('open');return}
  if((t=e.target.closest('.chips[data-for] button'))){const p=t.parentNode;p.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b===t));(p.dataset.for==='isf'?renderIssues:renderScopes)(t.dataset.f);return}
  if((t=e.target.closest('tr.sc'))){toggleScope(t)}
});
$('#bx').onclick=()=>document.querySelectorAll('.sec').forEach(s=>s.classList.add('open'));
$('#bc').onclick=()=>document.querySelectorAll('.sec').forEach(s=>s.classList.remove('open'));
let tmr;$('#q').oninput=e=>{clearTimeout(tmr);tmr=setTimeout(()=>search(e.target.value),200)};
document.addEventListener('keydown',e=>{if(e.key==='/'&&document.activeElement.tagName!=='INPUT'){e.preventDefault();$('#q').focus()}});
</script></body></html>
'@

# =============================================================================
#  COMPARE DASHBOARD TEMPLATE (D = { mode:'compare', a:<source data>, b:<target data>, aKind, aSaved })
# =============================================================================
$CompareTemplate = @'
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-__SCRIPT_HASH__'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>DHCP Analyzer by Starkark98 - Compare</title>
<link rel="icon" type="image/png" href="data:image/png;base64,__ICON__">
<style>
__CSS__
.vs{color:var(--mut);margin:0 6px}.k b.verdict{font-size:16px;white-space:normal}
td.diffval{max-width:340px;word-break:break-word}
.filterNote{margin:0 0 8px}.filterNote button{margin-left:8px}
</style></head><body>
<div id="old"><b style="font-size:18px">DHCP Analyzer by Starkark98</b><br><br>
This dashboard requires a modern browser: <b>Microsoft Edge</b>, <b>Google Chrome</b> or <b>Firefox</b>.<br>
Internet Explorer is not supported. Copy this file to a PC with Edge or Chrome and open it there.</div>
<div class="top">
  <h1><img class="logo" src="data:image/png;base64,__ICON__" alt="">DHCP Analyzer<span class="by">by Starkark98</span><small id="sub"></small><span id="demo"></span></h1>
  <button id="bx">Expand all</button><button id="bc">Collapse all</button>
</div>
<main id="m"></main>
<footer id="ft"></footer>
<script>
document.getElementById('old').remove();
const D=__DATA__, WARN=80, CRIT=95;
__JSCOMMON__
/* ---------- normalization (every value is untrusted: esc() for text, num() for numbers) ---------- */
function norm(X){
  X=X||{}; ['scopes','failover','serverOptions','policies','classes','optionDefs','superscopes'].forEach(k=>X[k]=arr(X[k]));
  X.settings=X.settings||{}; X.serverOptions.forEach(o=>o.id=num(o.id)); X.policies.forEach(normPol);
  X.optionDefs.forEach(o=>o.id=num(o.id)); X.superscopes.forEach(s=>s.scopes=arr(s.scopes)); X.failover.forEach(f=>f.scopes=arr(f.scopes));
  X.scopes.forEach(s=>{['options','exclusions','reservations','policies'].forEach(k=>s[k]=arr(s[k]));
    s.inUse=num(s.inUse); s.free=num(s.free); s.options.forEach(o=>o.id=num(o.id)); s.policies.forEach(normPol)});
  return X;
}
const A=norm(D.a), B=norm(D.b);
const srcName=D.aKind==='baseline'||D.aKind==='report'?`${A.server} (${D.aKind} ${D.aSaved||''})`:String(A.server||'');
const srcKind=D.aKind==='baseline'?'Baseline file saved '+(D.aSaved||''):D.aKind==='report'?'Analysis report created '+(D.aSaved||''):'Live server';
/* a source created before 1.1.0 has no policies, classes, option definitions or superscopes: skip them, do not report false differences */
const PARTIAL=!!D.aPartial, PARTIAL_NOTE='The source was created by an older version of DHCP Analyzer: policies, classes, option definitions and superscopes are not compared.';
const tgtName=String(B.server||'');

/* ---------- comparison ---------- */
const DF=[]; const add=(sev,cat,obj,item,a,b)=>DF.push({sev,cat,obj:String(obj??''),item,a:a==null||a===''?'\u2014':String(a),b:b==null||b===''?'\u2014':String(b)});
const yn=v=>v==null?'n/a':(v?'Yes':'No');
const by=(list,key)=>{const m=new Map();list.forEach(x=>m.set(key(x),x));return m};
const keys=(m1,m2,sort)=>[...new Set([...m1.keys(),...m2.keys()])].sort(sort||((x,y)=>String(x).localeCompare(String(y))));
const macN=m=>String(m||'').toLowerCase().replace(/[^0-9a-f]/g,'');
/* compares two keyed lists: missing on target = sevMissing, only on target = sevExtra, different = sevDiff per field */
function cmpList(cat,obj,la,lb,key,label,fields,sevMissing,sevExtra,sort){
  const ma=by(la,key),mb=by(lb,key); let n=0;
  keys(ma,mb,sort).forEach(k=>{const x=ma.get(k),y=mb.get(k);
    if(!y){add(sevMissing,cat,obj,`${label(x)}: missing on target`,label(x),null);n++;return}
    if(!x){add(sevExtra,cat,obj,`${label(y)}: only on target`,null,label(y));n++;return}
    /* f.v: value shown, f.c: value compared (e.g. MAC addresses compared without separators) */
    fields.forEach(f=>{const va=f.v?f.v(x):x[f.k],vb=f.v?f.v(y):y[f.k],ca=f.c?f.c(x):va,cb=f.c?f.c(y):vb;
      if(String(ca??'')!==String(cb??'')){add(f.sev,cat,obj,`${label(x)}: ${f.t}`,va,vb);n++}})});
  return n;
}
const OPTF=[{k:'value',t:'value',sev:'warn'}], POLF=[{k:'en',t:'enabled',sev:'warn'},{k:'order',t:'processing order',sev:'warn'},{k:'conditions',t:'conditions',sev:'warn'},{k:'ranges',t:'IP ranges',sev:'warn'},{k:'opts',t:'options',sev:'warn'},{k:'lease',t:'lease duration',sev:'warn'}];
const optLbl=o=>pad(o.id)+' '+o.name, ipSort=(x,y)=>ipN(x)-ipN(y);

/* server */
if(String(A.server).toLowerCase()!==String(B.server).toLowerCase())add('info','Server','Server','Server name',A.server,B.server);
[['authorized','Authorized in AD','crit',yn],['auditOn','Audit log','warn',yn],['conflict','Conflict detection attempts','warn'],['dnsDyn','Dynamic DNS updates','warn'],
 ['dnsDel','Delete DNS records on lease expiry','warn',yn],['nameProt','Name protection','warn',yn],['dnsCred','DNS update credentials','warn'],
 ['allowOn','MAC allow list','warn',yn],['denyOn','MAC deny list','warn',yn],['allowN','MAC allow list entries','warn'],['denyN','MAC deny list entries','warn'],
 ['version','DHCP server version','info'],['backupInt','Database backup interval (min)','info']].forEach(([k,t,sev,f])=>{
  const va=f?f(A.settings[k]):A.settings[k],vb=f?f(B.settings[k]):B.settings[k]; if(String(va??'')!==String(vb??''))add(sev,'Server settings','Server',t,va,vb)});
cmpList('Server options','Server',A.serverOptions,B.serverOptions,o=>o.id,optLbl,OPTF,'crit','info',(x,y)=>x-y);
if(!PARTIAL){
cmpList('Server policies','Server',A.policies,B.policies,p=>p.name,p=>p.name,POLF,'crit','warn');
cmpList('Classes','Server',A.classes,B.classes,c=>c.type+'|'+c.name,c=>`${c.type} class ${c.name}`,[{k:'data',t:'data',sev:'warn'}],'crit','info');
cmpList('Option definitions','Server',A.optionDefs,B.optionDefs,o=>(o.vendor||'')+'|'+o.id,o=>optLbl(o)+(o.vendor?' ['+o.vendor+']':''),[{k:'type',t:'type',sev:'warn'},{k:'multi',t:'multi-valued',sev:'warn',v:o=>yn(o.multi)}],'crit','info');
cmpList('Superscopes','Server',A.superscopes,B.superscopes,s=>s.name,s=>s.name,[{k:'scopes',t:'member scopes',sev:'warn',v:s=>s.scopes.slice().sort(ipSort).join(', ')}],'warn','info');
}
cmpList('Failover','Server',A.failover,B.failover,f=>f.name,f=>f.name,[{k:'mode',t:'mode',sev:'warn'},{k:'partner',t:'partner',sev:'info'},{k:'state',t:'state',sev:'info'},{k:'scopes',t:'scopes',sev:'warn',v:f=>f.scopes.slice().sort(ipSort).join(', ')}],'warn','info');

/* scopes */
const SA=by(A.scopes,s=>s.id),SB=by(B.scopes,s=>s.id), ST=[];
keys(SA,SB,ipSort).forEach(id=>{const x=SA.get(id),y=SB.get(id),before=DF.length;
  if(!y){add('crit','Scope',id,'Scope missing on target',x.name,null);ST.push({id,name:x.name,status:'Only on source',s:x,t:null,n:1});return}
  if(!x){add('info','Scope',id,'Scope only on target',null,y.name);ST.push({id,name:y.name,status:'Only on target',s:null,t:y,n:1});return}
  /* scope failover membership is info: a missing relationship is already reported once at server level */
  [['name','Name','info'],['desc','Description','info'],['mask','Subnet mask','crit'],['start','Range start','crit'],['end','Range end','crit'],['lease','Lease duration','warn'],['failover','Failover relationship','info']]
    .forEach(([k,t,sev])=>{if(String(x[k]??'')!==String(y[k]??''))add(sev,'Scope',id,t,x[k],y[k])});
  if(!!x.active!==!!y.active)add('warn','Scope',id,'State'+(x.active&&!y.active?' (target inactive: expected before cut-over)':''),x.active?'Active':'Inactive',y.active?'Active':'Inactive');
  cmpList('Scope options',id,x.options,y.options,o=>o.id,optLbl,OPTF,'crit','info',(p,q)=>p-q);
  cmpList('Exclusions',id,x.exclusions,y.exclusions,e=>e.start+'-'+e.end,e=>e.start+' \u2013 '+e.end,[],'crit','warn');
  cmpList('Reservations',id,x.reservations,y.reservations,r=>r.ip,r=>r.ip+(r.name?' ('+r.name+')':''),
    [{k:'mac',t:'MAC / client id',sev:'crit',c:r=>macN(r.mac)},{k:'type',t:'type',sev:'warn'},{k:'name',t:'name',sev:'info'},{k:'desc',t:'description',sev:'info'}],'crit','warn',ipSort);
  if(!PARTIAL)cmpList('Scope policies',id,x.policies,y.policies,p=>p.name,p=>p.name,POLF,'crit','warn');
  const mine=DF.slice(before),n=mine.length,real=mine.filter(d=>d.sev!=='info').length;
  ST.push({id,name:y.name||x.name,status:real?'Different':n?'Minor differences':'Identical',s:x,t:y,n});
});
const SEVORD={crit:0,warn:1,info:2};
DF.sort((p,q)=>SEVORD[p.sev]-SEVORD[q.sev]);
DF.forEach(d=>d.cnt=1);
const nC=DF.filter(d=>d.sev==='crit').length,nW=DF.filter(d=>d.sev==='warn').length,nI=DF.filter(d=>d.sev==='info').length;
ST.forEach(r=>{const l=DF.filter(d=>d.obj===r.id);r.c=l.filter(d=>d.sev==='crit').length;r.w=l.filter(d=>d.sev==='warn').length;r.i=l.filter(d=>d.sev==='info').length});

/* ---------- page ---------- */
$('#sub').innerHTML=`Compare: ${esc(srcName)}<span class="vs">&rarr;</span>${esc(tgtName)} &middot; ${esc(B.generated||'')}`;
if(D.demo)$('#demo').innerHTML='<span class="demo">DEMO DATA</span>';
$('#ft').innerHTML=`DHCP Analyzer by <b>Starkark98</b> &middot; compare ${esc(srcName)} &rarr; ${esc(tgtName)} &middot; read-only report`;
const verdict=nC?['crit','Not equivalent']:nW?['warn','Review the differences']:['ok','Equivalent'];
const same=ST.filter(r=>r.status==='Identical'||r.status==='Minor differences').length,onlyS=ST.filter(r=>r.status==='Only on source').length,onlyT=ST.filter(r=>r.status==='Only on target').length;
const K=[['Verdict',verdict[1],verdict[0],'diff','verdict'],['Critical',nC,nC?'crit':'ok','diff'],['Warnings',nW,nW?'warn':'ok','diff'],['Info',nI,'info','diff'],
  ['Scopes identical',`${same} / ${ST.length}`,same===ST.length?'ok':'warn','cscope'],['Missing on target',onlyS,onlyS?'crit':'ok','cscope'],['Only on target',onlyT,onlyT?'info':'ok','cscope']];
let h='<div class="kpi">'+K.map(k=>`<div class="k ${k[2]}" data-go="${k[3]}"><span>${k[0]}</span><b class="${k[4]||''}">${k[1]}</b></div>`).join('')+'</div>';
h+=sec('diff','Differences',badge(DF.length,nC?'crit':nW?'warn':'ok'),chips('dff',[['all','All',DF.length],['crit','Critical',nC],['warn','Warnings',nW],['info','Info',nI]])+'<div id="fnote"></div><div id="dgrid"></div>'+
  '<div class="mut hint">Missing on target = critical, different = warning, only on target or cosmetic = info. Lease counts are not compared (they change all the time).</div>'+
  (PARTIAL?`<div class="hint twarn">${PARTIAL_NOTE}</div>`:''),true);
h+=sec('cscope','Scopes',badge(ST.length),'<div id="sgrid"></div><div class="mut hint">Click a scope to see only its differences.</div>',true);
const src=(X,kind)=>`<div class="kv">${kv('Server',esc(X.server))}${kind?kv('Source type',kind):''}${kv('Data collected',esc(X.generated||''))}${kv('Scopes',X.scopes.length)}${kv('Reservations',X.scopes.reduce((a,s)=>a+s.reservations.length,0))}${kv('Policies',X.policies.length+X.scopes.reduce((a,s)=>a+s.policies.length,0))}${kv('Failover relationships',X.failover.length)}</div>`;
h+=sec('srcs','Sources','',`<h3>Source (old)</h3>${src(A,esc(srcKind))}${PARTIAL?`<div class="hint twarn">${PARTIAL_NOTE}</div>`:''}<h3>Target (new)</h3>${src(B,'Live server')}`,false);
$('#m').innerHTML=h;

let curSev='all',curObj='';
function renderDiffs(){
  const L=DF.filter(d=>(curSev==='all'||d.sev===curSev)&&(!curObj||d.obj===curObj));
  $('#fnote').innerHTML=curObj?`<div class="filterNote mut">Showing only <b>${esc(curObj)}</b><button id="fclear">Show all</button></div>`:'';
  makeGrid($('#dgrid'),[{k:'sev',t:'Severity',sv:r=>SEVORD[r.sev],f:r=>`<span class="pill ${r.sev}">${SEVL[r.sev]}</span>`},{k:'cat',t:'Category'},{k:'obj',t:'Object',sv:r=>r.obj==='Server'?-1:ipN(r.obj)},{k:'item',t:'Difference'},
    {k:'a',t:'Source (old)',f:r=>`<span class="diffval">${esc(r.a)}</span>`},{k:'b',t:'Target (new)',f:r=>`<span class="diffval">${esc(r.b)}</span>`}],L,{empty:'No differences: source and target are aligned'});
}
const STC={'Identical':'ok','Minor differences':'ok','Different':'warn','Only on source':'crit','Only on target':'info'};
makeGrid($('#sgrid'),[{k:'id',t:'Scope',sv:r=>ipN(r.id),f:r=>`<a data-obj="${esc(r.id)}">${esc(r.id)}</a>`},{k:'name',t:'Name'},{k:'status',t:'Status',f:r=>`<span class="pill ${STC[r.status]}">${esc(r.status)}</span>`},
  {k:'c',t:'Critical',sv:r=>r.c,num:1,f:r=>z(r.c)},{k:'w',t:'Warnings',sv:r=>r.w,num:1,f:r=>z(r.w)},{k:'i',t:'Info',sv:r=>r.i,num:1,f:r=>z(r.i)},
  {k:'su',t:'In use (source)',sv:r=>r.s?r.s.inUse:-1,num:1,f:r=>r.s?fmt(r.s.inUse):'&ndash;'},{k:'tu',t:'In use (target)',sv:r=>r.t?r.t.inUse:-1,num:1,f:r=>r.t?fmt(r.t.inUse):'&ndash;'}],ST,{empty:'No scopes'});
renderDiffs();

document.addEventListener('click',e=>{
  let t;
  if((t=e.target.closest('#fclear'))){curObj='';renderDiffs();return}
  if((t=e.target.closest('[data-obj]'))){curObj=t.dataset.obj;renderDiffs();const s=$('#diff');s.classList.add('open');s.scrollIntoView({behavior:'smooth',block:'start'});return}
  if((t=e.target.closest('[data-go]'))){const s=document.getElementById(t.dataset.go);s.classList.add('open');s.scrollIntoView({behavior:'smooth',block:'start'});return}
  if((t=e.target.closest('.sec>h2'))){t.parentNode.classList.toggle('open');return}
  if((t=e.target.closest('.chips[data-for] button'))){const p=t.parentNode;p.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b===t));curSev=t.dataset.f;renderDiffs();return}
});
$('#bx').onclick=()=>document.querySelectorAll('.sec').forEach(s=>s.classList.add('open'));
$('#bc').onclick=()=>document.querySelectorAll('.sec').forEach(s=>s.classList.remove('open'));
</script></body></html>
'@

# =============================================================================
#  REPORT OUTPUT
# =============================================================================
# '<' only occurs inside JSON strings: \u003c keeps hostnames like "</script>" or "<!--" from breaking the page.
# The Content-Security-Policy lets only this exact inline script run, identified by its SHA-256 hash.
# The HTML parser turns CRLF into LF before hashing, so the page is normalised to LF first.
function Build-Html([string]$json, [string]$tpl = $Template) {
    $html = $tpl.Replace('__CSS__', $Css).Replace('__JSCOMMON__', $JsCommon).Replace('__ICON__', $IconPng).Replace('__DATA__', $json.Replace('<', '\u003c')).Replace("`r`n", "`n")
    $s = $html.IndexOf('<script>') + 8; $e = $html.IndexOf('</script>', $s)
    $sha = [Security.Cryptography.SHA256]::Create()
    $hash = [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($html.Substring($s, $e - $s)))); $sha.Dispose()
    $html.Substring(0, $s).Replace('__SCRIPT_HASH__', $hash) + $html.Substring($s)   # placeholder replaced in the <head> only
}
function Save-Report([string]$json, [string]$server, [string]$path, [string]$tpl = $Template, [string]$prefix = 'DhcpReport') {
    if ($path) {
        $path = Resolve-OutHtml $path $server $prefix
        $dir  = Split-Path $path -Parent
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { [void](New-Item $dir -ItemType Directory -Force) }
    }
    else { $path = Join-Path $env:TEMP ("{0}_{1}_{2}.html" -f $prefix, ($server -replace '[^\w.-]', '_'), (Get-Date -Format yyyyMMdd_HHmmss)) }
    [IO.File]::WriteAllText($path, (Build-Html $json $tpl), [Text.UTF8Encoding]::new($false))
    $path
}
function Find-Browser {
    $cands = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    )
    foreach ($exe in 'msedge.exe', 'chrome.exe', 'firefox.exe') {
        try { $cands += (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$exe" -ErrorAction Stop).'(default)' } catch { }
    }
    $cands | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
}
function Open-Report([string]$path) {
    $b = Find-Browser
    if (-not $b) { return $false }
    Start-Process -FilePath $b -ArgumentList "`"$path`""
    return $true
}
function Show-Message([string]$text, [string]$icon = 'Warning') {
    try { Add-Type -AssemblyName PresentationFramework; [void][Windows.MessageBox]::Show($text, 'DHCP Analyzer', 'OK', $icon) }
    catch { Write-Warning $text }
}
# Last-resort handler: the launchers start PowerShell with a hidden console, so an unexpected error would otherwise vanish silently
trap {
    if ($NoGui) { break }
    Show-Message "$AppName stopped because of an unexpected error:`n$($_.Exception.Message)" 'Error'
    break
}
# Validate the command-line input before using it anywhere
function Resolve-UserPath([string]$path) {   # absolute path; a trailing '\' is dropped (before a closing quote it would escape the quote on relaunch)
    $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
    if ($path -match '[\\/]$') { [void](New-Item $path -ItemType Directory -Force); if ($path.Length -gt 3) { $path = $path.TrimEnd('\', '/') } }
    $path
}
$cliErr = $null
try {
    if ($DhcpServer -and -not (Test-ServerName $DhcpServer))   { throw "Invalid DHCP server name: '$DhcpServer'. Use a host name, an FQDN or an IP address." }
    if ($CompareWith -and -not (Test-ServerName $CompareWith)) { throw "Invalid target server name: '$CompareWith'. Use a host name, an FQDN or an IP address." }
    if ($Baseline -and -not $CompareWith) { throw '-Baseline needs -CompareWith: the baseline is the source, -CompareWith is the target server.' }
    if ($Baseline -and $DhcpServer)       { throw 'Use either -DhcpServer (a live source server) or -Baseline (a saved file) as the source, not both.' }
    if ($CompareWith -and $DhcpServer -and $CompareWith -eq $DhcpServer) { throw "Source and target are the same server ($DhcpServer): choose two different servers, or compare the server with a baseline saved earlier." }
    if ($SaveBaseline -and $CompareWith)  { throw '-SaveBaseline saves the data of an analysis: use it without -CompareWith.' }
    if ($OutHtml)      { $OutHtml = Resolve-UserPath $OutHtml; [void](Resolve-OutHtml $OutHtml 'check') }          # throws on a wrong extension
    if ($SaveBaseline) { $SaveBaseline = Resolve-UserPath $SaveBaseline; [void](Resolve-BaselinePath $SaveBaseline 'check') }
    if ($Baseline)     { $Baseline = Resolve-UserPath $Baseline; [void](Read-Baseline $Baseline) }                  # throws if missing or not a baseline
} catch { $cliErr = $_.Exception.Message }
if ($cliErr) { if ($NoGui) { throw $cliErr } else { Show-Message $cliErr 'Error'; return } }
$NoBrowserMsg = "Report created, but no modern browser (Edge, Chrome or Firefox) was found on this PC: Internet Explorer cannot display the dashboard. Use 'Save as' or 'Show in folder' and open the file on a PC with Edge or Chrome, or run DHCP Analyzer from your workstation with the RSAT DHCP tools."

# Runs the collector in this thread (command-line mode). $role ('Source (old)'/'Target (new)') prefixes the error message.
function Invoke-Collect([string]$server, [bool]$scan, [bool]$light, [string]$role = '') {
    $sync = [hashtable]::Synchronized(@{ Status = ''; Progress = 0; Done = $false; Error = $null; Json = $null })
    & $Collector $server $scan $sync $light
    if ($sync.Error) { if ($role) { throw "$role server $server could not be read: $($sync.Error)" } else { throw $sync.Error } }
    $sync.Json
}
function Show-Demo([string]$path) {
    Write-Host "Demo dashboard: $path" -ForegroundColor Green
    if ($NoOpen) { return }
    if (-not (Open-Report $path)) {
        try { Start-Process explorer.exe "/select,`"$path`"" } catch { }
        Show-Message "The demo dashboard was created, but no modern browser (Edge, Chrome or Firefox) was found on this PC. Internet Explorer cannot display it.`n`nThe file is now selected in File Explorer: copy it to a PC with Edge or Chrome and open it there.`n`n$path"
    }
}

# =============================================================================
#  DEMO AND COMMAND-LINE MODES
# =============================================================================
if ($Demo -or $DemoCompare) {
    try {
        if ($DemoCompare) {
            $pair = New-DemoCompareData
            $json = New-CompareJson ($pair[0] | ConvertTo-Json -Depth 8 -Compress) ($pair[1] | ConvertTo-Json -Depth 8 -Compress) 'server' '' $true
            Show-Demo (Save-Report $json 'DEMO' $OutHtml $CompareTemplate 'DhcpCompare')
        } else {
            Show-Demo (Save-Report ((New-DemoData) | ConvertTo-Json -Depth 8 -Compress) 'DEMO' $OutHtml)
        }
    } catch { if ($NoGui) { throw } else { Show-Message "The demo could not be created:`n$($_.Exception.Message)" 'Error' } }
    return
}

if ($NoGui) {
    if ($CompareWith) {
        if ($Baseline) {
            $base = Read-Baseline $Baseline; $srcJson = $base.json; $srcName = $base.server
            Write-Host "Source: $($base.kind) of $($base.server) from $($base.saved)$(if ($base.partial) { ' (older version: policies, classes, option definitions and superscopes are not compared)' })" -ForegroundColor Cyan
        } else {
            while (-not (Test-ServerName $DhcpServer) -or $DhcpServer -eq $CompareWith) { $DhcpServer = (Read-Host 'Source (old) DHCP server name').Trim() }
            Write-Host "Reading source $DhcpServer..." -ForegroundColor Cyan
            $srcJson = Invoke-Collect $DhcpServer $false $true 'Source (old)'; $srcName = $DhcpServer
        }
        Write-Host "Reading target $CompareWith..." -ForegroundColor Cyan
        $tgtJson = Invoke-Collect $CompareWith $false $true 'Target (new)'
        $json = if ($Baseline) { New-CompareJsonFromBaseline $base $tgtJson } else { New-CompareJson $srcJson $tgtJson }
        $path = Save-Report $json "${srcName}_vs_$CompareWith" $OutHtml $CompareTemplate 'DhcpCompare'
    } else {
        while (-not (Test-ServerName $DhcpServer)) { $DhcpServer = (Read-Host 'DHCP server name (host name, FQDN or IP)').Trim() }
        Write-Host "Analyzing $DhcpServer..." -ForegroundColor Cyan
        $json = Invoke-Collect $DhcpServer (-not $SkipExclusionScan) $false
        $path = Save-Report $json $DhcpServer $OutHtml
        if ($SaveBaseline) { Write-Host "Baseline: $(Save-Baseline $json $DhcpServer $SaveBaseline)" -ForegroundColor Green }
    }
    Write-Host "Dashboard: $path" -ForegroundColor Green
    if (-not $NoOpen -and -not (Open-Report $path)) { Write-Warning $NoBrowserMsg }
    return
}

# =============================================================================
#  GRAPHICAL INTERFACE
# =============================================================================
$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
$relArgs = "-NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File `"$PSCommandPath`" -NoElevate"
if ($DhcpServer) { $relArgs += " -DhcpServer `"$DhcpServer`"" }
if ($SkipExclusionScan) { $relArgs += ' -SkipExclusionScan' }
if ($CompareWith) { $relArgs += " -CompareWith `"$CompareWith`"" }
if ($Baseline) { $relArgs += " -Baseline `"$Baseline`"" }
if ($SaveBaseline) { $relArgs += " -SaveBaseline `"$SaveBaseline`"" }
# Already validated and resolved to an absolute path above (the elevated process starts in System32)
if ($OutHtml) { $relArgs += " -OutHtml `"$OutHtml`"" }
if (-not $isAdmin -and -not $NoElevate) {
    try { Start-Process powershell.exe -Verb RunAs -ArgumentList $relArgs; return }
    catch { }   # UAC declined: continue without elevation
}
if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
    Start-Process powershell.exe -ArgumentList $relArgs
    return
}
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

[xml]$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="DHCP Analyzer - by Starkark98" Width="560" SizeToContent="Height" WindowStartupLocation="CenterScreen"
        ResizeMode="CanMinimize" Background="#F4F5F7" FontFamily="Segoe UI" FontSize="13">
  <Window.Resources>
    <Style x:Key="Seg" TargetType="RadioButton">
      <Setter Property="Cursor" Value="Hand"/>
      <Setter Property="Template">
        <Setter.Value>
          <ControlTemplate TargetType="RadioButton">
            <Border x:Name="Bd" Background="Transparent" CornerRadius="6" Padding="14,7">
              <ContentPresenter HorizontalAlignment="Center"/>
            </Border>
            <ControlTemplate.Triggers>
              <Trigger Property="IsChecked" Value="True">
                <Setter TargetName="Bd" Property="Background" Value="White"/>
                <Setter Property="Foreground" Value="#2563EB"/>
                <Setter Property="FontWeight" Value="SemiBold"/>
              </Trigger>
              <Trigger Property="IsEnabled" Value="False"><Setter Property="Opacity" Value="0.5"/></Trigger>
            </ControlTemplate.Triggers>
          </ControlTemplate>
        </Setter.Value>
      </Setter>
    </Style>
  </Window.Resources>
  <Border Margin="16" Padding="24" Background="White" CornerRadius="10">
    <StackPanel>
      <Grid Margin="0,0,0,18">
        <Grid.ColumnDefinitions><ColumnDefinition Width="Auto"/><ColumnDefinition Width="*"/></Grid.ColumnDefinitions>
        <Image x:Name="ImgLogo" Width="68" Height="68" Margin="0,0,16,0" VerticalAlignment="Center" RenderOptions.BitmapScalingMode="HighQuality"/>
        <StackPanel Grid.Column="1" VerticalAlignment="Center">
          <StackPanel Orientation="Horizontal">
            <TextBlock Text="DHCP Analyzer" FontSize="24" FontWeight="SemiBold" Foreground="#1F2328"/>
            <TextBlock Text="by Starkark98" FontSize="13" FontStyle="Italic" Foreground="#2563EB" VerticalAlignment="Bottom" Margin="8,0,0,5"/>
            <TextBlock x:Name="TxtVer" FontSize="11" Foreground="#9CA3AF" VerticalAlignment="Bottom" Margin="8,0,0,6"/>
          </StackPanel>
          <TextBlock Text="Read-only health check of Windows DHCP servers, and 1:1 comparison for migrations."
                     Foreground="#6B7280" TextWrapping="Wrap" Margin="0,4,0,0"/>
        </StackPanel>
      </Grid>
      <Border Background="#F0F2F5" CornerRadius="8" Padding="3" Margin="0,0,0,16" HorizontalAlignment="Left">
        <StackPanel Orientation="Horizontal">
          <RadioButton x:Name="RbAnalyze" Style="{StaticResource Seg}" GroupName="Mode" IsChecked="True" Content="Analyze a server"/>
          <RadioButton x:Name="RbCompare" Style="{StaticResource Seg}" GroupName="Mode" Content="Compare two servers (migration)"/>
        </StackPanel>
      </Border>
      <TextBlock x:Name="LblSrc" Text="DHCP server" FontWeight="SemiBold" Foreground="#1F2328"/>
      <Grid Margin="0,6,0,14">
        <Grid.ColumnDefinitions><ColumnDefinition Width="*"/><ColumnDefinition Width="Auto"/></Grid.ColumnDefinitions>
        <ComboBox x:Name="CmbServer" IsEditable="True" FontSize="15" Padding="6"/>
        <Button x:Name="BtnBrowse" Grid.Column="1" Content="Baseline..." Padding="12,0" Margin="8,0,0,0" Cursor="Hand" Visibility="Collapsed"
                ToolTip="Use a baseline file saved earlier (for example from a server that is already switched off) as the source"/>
      </Grid>
      <TextBlock x:Name="TxtSrcHint" Text="Server name, a baseline saved earlier (.json) or an analysis report (.html)" Foreground="#6B7280" FontSize="12" Margin="0,-8,0,12" Visibility="Collapsed"/>
      <StackPanel x:Name="PnlTarget" Visibility="Collapsed">
        <TextBlock Text="Target (new)" FontWeight="SemiBold" Foreground="#1F2328"/>
        <ComboBox x:Name="CmbTarget" IsEditable="True" FontSize="15" Padding="6" Margin="0,6,0,10"/>
        <TextBlock Foreground="#6B7280" FontSize="12" TextWrapping="Wrap"
                   Text="Compares the configuration of both servers: scopes, options, exclusions, reservations, policies, classes, option definitions, superscopes, failover and server settings. Both servers must be reachable and are only read."/>
      </StackPanel>
      <StackPanel x:Name="PnlScan">
        <CheckBox x:Name="ChkScan" IsChecked="True" Foreground="#1F2328">
          <TextBlock TextWrapping="Wrap">Check real usage of excluded IPs (ping, ports, ARP, DNS)</TextBlock>
        </CheckBox>
        <TextBlock Text="Takes a few extra minutes. ARP works only for subnets this PC is connected to."
                   Foreground="#6B7280" FontSize="12" TextWrapping="Wrap" Margin="22,2,0,0"/>
      </StackPanel>
      <Button x:Name="BtnRun" Content="Analyze" Height="40" Margin="0,22,0,0" FontSize="15" FontWeight="SemiBold"
              IsDefault="True" Background="#2563EB" Foreground="White" BorderThickness="0" Cursor="Hand"/>
      <Button x:Name="BtnDemo" Content="No server at hand? Try the demo with sample data" Margin="0,10,0,0" Padding="0,4"
              Background="Transparent" BorderThickness="0" Foreground="#2563EB" Cursor="Hand" HorizontalAlignment="Center"/>
      <ProgressBar x:Name="Bar" Height="8" Margin="0,14,0,0" Minimum="0" Maximum="100" Visibility="Collapsed" Foreground="#2563EB"/>
      <TextBox x:Name="TxtStatus" Margin="0,8,0,0" Foreground="#4B5563" TextWrapping="Wrap" IsReadOnly="True"
               BorderThickness="0" Background="Transparent" Padding="0"/>
      <WrapPanel x:Name="PnlDone" Margin="0,14,0,0" Visibility="Collapsed">
        <Button x:Name="BtnOpen" Content="Open dashboard" Padding="14,6" Margin="0,0,8,8" Cursor="Hand"/>
        <Button x:Name="BtnSave" Content="Save as..." Padding="14,6" Margin="0,0,8,8" Cursor="Hand"/>
        <Button x:Name="BtnBaseline" Content="Save baseline..." Padding="14,6" Margin="0,0,8,8" Cursor="Hand"
                ToolTip="Saves the collected data as a .json file, to compare a new server with it later"/>
        <Button x:Name="BtnFolder" Content="Show in folder" Padding="14,6" Margin="0,0,0,8" Cursor="Hand"/>
      </WrapPanel>
    </StackPanel>
  </Border>
</Window>
'@

try { $win = [Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($xaml)) }
catch { Show-Message "DHCP Analyzer could not open its window:`n$($_.Exception.Message)" 'Error'; return }
$ui  = @{}
'RbAnalyze', 'RbCompare', 'LblSrc', 'TxtSrcHint', 'CmbServer', 'BtnBrowse', 'PnlTarget', 'CmbTarget', 'PnlScan', 'ChkScan', 'BtnRun', 'BtnDemo', 'Bar', 'TxtStatus',
'PnlDone', 'BtnOpen', 'BtnSave', 'BtnBaseline', 'BtnFolder', 'TxtVer' | ForEach-Object { $ui[$_] = $win.FindName($_) }
$ui.TxtVer.Text = "v$AppVersion"
function ConvertTo-Image([string]$b64) {
    $bi = [Windows.Media.Imaging.BitmapImage]::new()
    $bi.BeginInit(); $bi.StreamSource = [IO.MemoryStream]::new([Convert]::FromBase64String($b64)); $bi.CacheOption = 'OnLoad'; $bi.EndInit(); $bi.Freeze()
    $bi
}
try { $win.Icon = ConvertTo-Image $IconPng; $win.FindName('ImgLogo').Source = ConvertTo-Image $LogoPng } catch { }   # cosmetic only

$cfgDir   = Join-Path $env:APPDATA 'DhcpAnalyzer'
$lastFile = Join-Path $cfgDir 'last.txt'
$lastTgt  = Join-Path $cfgDir 'last-target.txt'
$script:report = $null; $script:job = $null; $script:run = $null; $script:json = $null

function Set-Status([string]$text, [bool]$isError = $false) {
    $ui.TxtStatus.Text = $text
    $ui.TxtStatus.Foreground = if ($isError) { [Windows.Media.Brushes]::Firebrick } else { [Windows.Media.Brushes]::DimGray }
}
function Set-Busy([bool]$busy) {
    foreach ($n in 'RbAnalyze', 'RbCompare', 'CmbServer', 'BtnBrowse', 'CmbTarget', 'ChkScan', 'BtnRun', 'BtnDemo') { $ui[$n].IsEnabled = -not $busy }
    $ui.Bar.Visibility = if ($busy) { 'Visible' } else { 'Collapsed' }
    if ($busy) { $ui.PnlDone.Visibility = 'Collapsed'; $ui.Bar.Value = 0 }
}
function Update-Mode {
    $cmp = [bool]$ui.RbCompare.IsChecked
    $ui.LblSrc.Text = if ($cmp) { 'Source (old)' } else { 'DHCP server' }
    $ui.TxtSrcHint.Visibility = if ($cmp) { 'Visible' } else { 'Collapsed' }
    $ui.BtnBrowse.Visibility = if ($cmp) { 'Visible' } else { 'Collapsed' }
    $ui.PnlTarget.Visibility = if ($cmp) { 'Visible' } else { 'Collapsed' }
    $ui.PnlScan.Visibility   = if ($cmp) { 'Collapsed' } else { 'Visible' }
    $ui.BtnRun.Content  = if ($cmp) { 'Compare' } else { 'Analyze' }
    $ui.BtnDemo.Content = if ($cmp) { 'No servers at hand? Try the comparison demo with sample data' } else { 'No server at hand? Try the demo with sample data' }
    if (-not $cmp -and "$($ui.CmbServer.Text)" -match '(?i)\.(json|html?)$') { $ui.CmbServer.Text = '' }   # a baseline or report is only a compare source
}
function Show-Report([string]$okText) {
    $ui.PnlDone.Visibility = 'Visible'
    $ui.BtnBaseline.Visibility = if ($script:run -and $script:run.Mode -eq 'analyze') { 'Visible' } else { 'Collapsed' }
    if (Open-Report $script:report) { Set-Status $okText } else { Set-Status $NoBrowserMsg $true }
}

# Authorized DHCP servers from AD + last servers used
$win.Add_ContentRendered({
    try { Import-Module DhcpServer -ErrorAction Stop; Get-DhcpServerInDC | Sort-Object DnsName | ForEach-Object { [void]$ui.CmbServer.Items.Add($_.DnsName); [void]$ui.CmbTarget.Items.Add($_.DnsName) } }
    catch { if (-not (Get-Module -ListAvailable DhcpServer)) { Set-Status 'DhcpServer module not found: install the RSAT "DHCP Server Tools" to analyze a server. The demos work anyway.' $true } }
})
function Read-Last([string]$file) { try { if (Test-Path $file) { $v = "$(Get-Content $file -Raw)".Trim(); if (Test-ServerName $v) { return $v } } } catch { }; '' }
if ($CompareWith) { $ui.RbCompare.IsChecked = $true; $ui.CmbTarget.Text = $CompareWith; $ui.CmbServer.Text = $(if ($Baseline) { $Baseline } else { $DhcpServer }) }
elseif ($DhcpServer) { $ui.CmbServer.Text = $DhcpServer }
else { $ui.CmbServer.Text = Read-Last $lastFile; $ui.CmbTarget.Text = Read-Last $lastTgt }
if ($SkipExclusionScan) { $ui.ChkScan.IsChecked = $false }
Update-Mode
$ui.RbAnalyze.Add_Checked({ Update-Mode }); $ui.RbCompare.Add_Checked({ Update-Mode })

# ---- Background work: one or two collector runs ("phases"), polled by a timer ----
function Start-Phase {
    $ph = $script:run.Phases[$script:run.Index]
    $script:sync = [hashtable]::Synchronized(@{ Status = 'Starting...'; Progress = 0; Done = $false; Error = $null; Json = $null })
    $script:job  = [powershell]::Create()
    [void]$script:job.AddScript($Collector.ToString()).AddArgument($ph.Server).AddArgument($ph.Scan).AddArgument($script:sync).AddArgument($ph.Light)
    $script:handle = $script:job.BeginInvoke()
}
function Start-Run($run) {
    $script:run = $run; $run.Index = 0; $run.Results = @{}
    Set-Busy $true
    Start-Phase
    $timer.Start()
}
function Complete-Run {
    $r = $script:run
    # same inputs as the previous run: update the same report file (refresh); otherwise a new file
    $path = if ($r.Reuse) { $r.Reuse } else { $OutHtml }
    $done = if ($r.Reuse) { 'Same inputs as before: the report was updated (press F5 if the tab is already open).' } else { 'Dashboard opened in your browser.' }
    if ($r.Mode -eq 'analyze') {
        $script:json   = $r.Results['main']
        $script:report = Save-Report $script:json $r.Server $path
        if ($SaveBaseline) { try { [void](Save-Baseline $script:json $r.Server $SaveBaseline) } catch { } }
        Show-Report "Analysis completed. $done"
    } else {
        $src  = if ($r.Baseline) { $r.Baseline.json } else { $r.Results['source'] }
        $json = if ($r.Baseline) { New-CompareJsonFromBaseline $r.Baseline $r.Results['target'] } else { New-CompareJson $src $r.Results['target'] }
        $script:json   = $null
        $script:report = Save-Report $json "$($r.SrcName)_vs_$($r.Target)" $path $CompareTemplate 'DhcpCompare'
        Show-Report "Comparison completed. $done"
    }
}

$timer = [Windows.Threading.DispatcherTimer]::new()
$timer.Interval = [TimeSpan]::FromMilliseconds(250)
$timer.Add_Tick({
    try {
        $r = $script:run; $ph = $r.Phases[$r.Index]; $n = $r.Phases.Count
        $ui.Bar.Value = [int](($r.Index * 100 + $script:sync.Progress) / $n)
        if ($script:sync.Status) { Set-Status $(if ($ph.Label) { "$($ph.Label): $($script:sync.Status)" } else { $script:sync.Status }) }
        if (-not $script:sync.Done) { return }
        try { [void]$script:job.EndInvoke($script:handle) } catch { }
        $script:job.Dispose(); $script:job = $null
        if ($script:sync.Error) {
            $timer.Stop(); Set-Busy $false
            Set-Status $(if ($ph.Label) { "$($ph.Label) $($ph.Server) could not be read: $($script:sync.Error)" } else { "Error: $($script:sync.Error)" }) $true
            return
        }
        $r.Results[$ph.Key] = $script:sync.Json
        $r.Index++
        if ($r.Index -lt $n) { Start-Phase; return }
        $timer.Stop(); Set-Busy $false
        Complete-Run
    } catch { $timer.Stop(); Set-Busy $false; Set-Status "Error: $($_.Exception.Message)" $true }
})

# Reads and validates the window fields; returns a run description or $null (the error is shown in the status line)
function Get-RunFromInput {
    $src = "$($ui.CmbServer.Text)".Trim()
    if (-not $ui.RbCompare.IsChecked) {
        if (-not $src) { Set-Status 'Enter the DHCP server name.' $true; return $null }
        if (-not (Test-ServerName $src)) { Set-Status 'Invalid server name: use a host name, an FQDN or an IP address (no spaces or quotes).' $true; return $null }
        try { if (-not (Test-Path $cfgDir)) { [void](New-Item $cfgDir -ItemType Directory) }; Set-Content $lastFile $src } catch { }
        $scan = [bool]$ui.ChkScan.IsChecked
        return @{ Mode = 'analyze'; Server = $src; Key = "analyze|$($src.ToLower())|$scan"; Phases = @(@{ Key = 'main'; Server = $src; Scan = $scan; Light = $false; Label = '' }) }
    }
    $tgt = "$($ui.CmbTarget.Text)".Trim()
    if (-not $src) { Set-Status 'Enter the source (old) server, or choose a baseline file with Baseline...' $true; return $null }
    if (-not $tgt) { Set-Status 'Enter the target (new) server.' $true; return $null }
    if (-not (Test-ServerName $tgt)) { Set-Status 'Invalid target server name: use a host name, an FQDN or an IP address (no spaces or quotes).' $true; return $null }
    $run = @{ Mode = 'compare'; Target = $tgt; Key = "compare|$($src.ToLower())|$($tgt.ToLower())"; Phases = @() }
    if ($src -match '(?i)\.(json|html?)$') {
        try { $run.Baseline = Read-Baseline $src; $run.BaselinePath = $src } catch { Set-Status $_.Exception.Message $true; return $null }
        $run.SrcName = $run.Baseline.server
    } else {
        if (-not (Test-ServerName $src)) { Set-Status 'Invalid source server name: use a host name, an FQDN or an IP address, or choose a baseline file.' $true; return $null }
        if ($src -eq $tgt) { Set-Status "Source and target are the same server ($src): choose two different servers, or compare the server with a baseline saved earlier." $true; return $null }
        $run.SrcName = $src
        $run.Phases += @{ Key = 'source'; Server = $src; Scan = $false; Light = $true; Label = 'Source (old) server' }
        try { if (-not (Test-Path $cfgDir)) { [void](New-Item $cfgDir -ItemType Directory) }; Set-Content $lastFile $src } catch { }
    }
    $run.Phases += @{ Key = 'target'; Server = $tgt; Scan = $false; Light = $true; Label = 'Target (new) server' }
    try { if (-not (Test-Path $cfgDir)) { [void](New-Item $cfgDir -ItemType Directory) }; Set-Content $lastTgt $tgt } catch { }
    $run
}

$ui.BtnRun.Add_Click({
    try {
        $r = Get-RunFromInput
        if (-not $r) { return }
        # same mode and inputs as the last real run (not a demo): refresh the same report file
        if ($script:run -and $script:report -and $script:run.Key -eq $r.Key -and (Test-Path -LiteralPath $script:report)) { $r.Reuse = $script:report }
        Start-Run $r
    } catch { Set-Busy $false; Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnBrowse.Add_Click({
    try {
        $dlg = [Microsoft.Win32.OpenFileDialog]::new()
        $dlg.Filter = 'DHCP Analyzer baseline or report (*.json;*.html;*.htm)|*.json;*.html;*.htm'; $dlg.Title = 'Choose a baseline or a report saved with DHCP Analyzer'
        if ($dlg.ShowDialog($win)) {
            $b = Read-Baseline $dlg.FileName
            $ui.CmbServer.Text = $dlg.FileName
            $what = if ($b.kind -eq 'report') { "Analysis report of $($b.server), created $($b.saved)" } else { "Baseline of $($b.server), saved $($b.saved) (DHCP Analyzer $($b.version))" }
            Set-Status $(if ($b.partial) { "$what. Created by an older version: policies, classes, option definitions and superscopes will not be compared." } else { "$what." })
        }
    } catch { Set-Status $_.Exception.Message $true }
})
$ui.BtnDemo.Add_Click({
    try {
        $script:run = $null; $script:json = $null
        if ($ui.RbCompare.IsChecked) {
            $pair = New-DemoCompareData
            $script:report = Save-Report (New-CompareJson ($pair[0] | ConvertTo-Json -Depth 8 -Compress) ($pair[1] | ConvertTo-Json -Depth 8 -Compress) 'server' '' $true) 'DEMO' $null $CompareTemplate 'DhcpCompare'
            Show-Report 'Comparison demo opened in your browser (fictitious data).'
        } else {
            $script:report = Save-Report ((New-DemoData) | ConvertTo-Json -Depth 8 -Compress) 'DEMO' $null
            Show-Report 'Demo dashboard opened in your browser (fictitious data).'
        }
    } catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnOpen.Add_Click({
    try { if ($script:report -and -not (Open-Report $script:report)) { Set-Status $NoBrowserMsg $true } }
    catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnFolder.Add_Click({
    try { if ($script:report) { Start-Process explorer.exe "/select,`"$script:report`"" } }
    catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnSave.Add_Click({
    try {
        if (-not $script:report) { return }
        $dlg = [Microsoft.Win32.SaveFileDialog]::new()
        $dlg.Filter = 'HTML dashboard (*.html)|*.html'; $dlg.FileName = [IO.Path]::GetFileName($script:report)
        if ($dlg.ShowDialog($win)) {
            if ($dlg.FileName -ne $script:report) { Copy-Item $script:report $dlg.FileName -Force }
            Set-Status "Saved to $($dlg.FileName)"
        }
    } catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnBaseline.Add_Click({
    try {
        if (-not $script:json -or -not $script:run) { return }
        $dlg = [Microsoft.Win32.SaveFileDialog]::new()
        $dlg.Filter = 'DHCP Analyzer baseline (*.json)|*.json'
        $dlg.FileName = "DhcpBaseline_{0}_{1}.json" -f ($script:run.Server -replace '[^\w.-]', '_'), (Get-Date -Format yyyyMMdd_HHmm)
        if ($dlg.ShowDialog($win)) { Set-Status "Baseline saved to $(Save-Baseline $script:json $script:run.Server $dlg.FileName). Use it later as the source of a comparison." }
    } catch { Set-Status "Error: $($_.Exception.Message)" $true }
})
$win.Add_Closing({ if ($script:job) { try { $script:job.Stop(); $script:job.Dispose() } catch { } } })

[void]$win.ShowDialog()
