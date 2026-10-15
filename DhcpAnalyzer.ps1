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

.EXAMPLE
  .\DhcpAnalyzer.ps1
.EXAMPLE
  .\DhcpAnalyzer.ps1 -Demo
.EXAMPLE
  .\DhcpAnalyzer.ps1 -DhcpServer DHCP01 -NoGui -OutHtml C:\Reports\dhcp.html

.NOTES
  Author : Starkark98
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
    [switch]$NoOpen
)

$ErrorActionPreference = 'Stop'
$AppName    = 'DHCP Analyzer'
$AppVersion = '1.0.1'

function IpToInt([string]$ip) { $b = [Net.IPAddress]::Parse($ip).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function IntToIp([uint32]$n)  { $b = [BitConverter]::GetBytes($n); [Array]::Reverse($b); [Net.IPAddress]::new([byte[]]$b).ToString() }

# =============================================================================
#  ANALYSIS ENGINE (runs in a background runspace)
# =============================================================================
$Collector = {
    param($Server, $Scan, $Sync)
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
                $isLocal = ($Server -in @('localhost', '127.0.0.1', '.', $env:COMPUTERNAME)) -or ($Server -like "$env:COMPUTERNAME.*")
                $aDir    = if ($isLocal) { $aPath } else { "\\$Server\" + ($aPath -replace '^([A-Za-z]):', '$1$') }
                $ci      = [Globalization.CultureInfo]::InvariantCulture
                foreach ($file in @(Get-ChildItem -Path $aDir -Filter 'DhcpSrvLog-*.log' -ErrorAction Stop)) {
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
            $ls  = @(Safe { Get-DhcpServerv4Lease -ComputerName $Server -ScopeId $id -AllLeases } | Where-Object { $_ })
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
                scan = $scanRes
            }
        }

        Step 'Building dashboard...' 97
        $data = [pscustomobject]@{
            server = $Server; generated = (Get-Date).ToString('yyyy-MM-dd HH:mm'); scanned = [bool]$Scan; demo = $false
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
            reservations = @($rs); leases = @($ls); scan = $scan }
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
        server = "DHCP01.$dom"; generated = $now.ToString('yyyy-MM-dd HH:mm'); scanned = $true; demo = $true
        settings = [pscustomobject]@{ authorized = $true; conflict = 0; auditOn = $true; auditPath = 'C:\Windows\system32\dhcp'
            backupPath = 'C:\Windows\system32\dhcp\backup'; backupInt = '60'; dnsDyn = 'OnClientRequest'; dnsDel = $true; nameProt = $false; dnsCred = ''
            service = 'Running'; startType = 'Automatic'; version = '10.0'; allowOn = $false; denyOn = $true; allowN = 0; denyN = 3 }
        serverOptions = @(
            [pscustomobject]@{ id = 6;  name = 'DNS Servers';     value = '10.10.0.10, 10.10.0.11' },
            [pscustomobject]@{ id = 15; name = 'DNS Domain Name'; value = $dom },
            [pscustomobject]@{ id = 42; name = 'NTP Servers';     value = '10.10.0.10' })
        failover = @([pscustomobject]@{ name = 'dhcp01-dhcp02'; partner = "DHCP02.$dom"; mode = 'LoadBalance'; state = 'Normal'; role = ''
            mclt = '1 h'; lb = '50'; reserve = ''; auto = $false; switchInt = ''; scopes = @('10.10.0.0', '10.10.8.0', '10.30.0.0', '10.40.0.0') })
        scopes = @($s1, $s2, $s3, $s4, $s5, $s6)
        logs = $logs
    }
}

# =============================================================================
#  HTML DASHBOARD TEMPLATE (data is injected in place of __DATA__)
# =============================================================================
$Template = @'
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DHCP Analyzer by Starkark98</title>
<style>
:root{--bg:#f4f5f7;--card:#fff;--tx:#1f2328;--mut:#6b7280;--bd:#e5e7eb;--hd:#f0f2f5;--ok:#16a34a;--warn:#d97706;--crit:#dc2626;--info:#2563eb;--acc:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#111418;--card:#1b1f24;--tx:#e6e8eb;--mut:#9aa3ad;--bd:#2c323a;--hd:#232830}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 'Segoe UI',system-ui,Arial,sans-serif;background:var(--bg);color:var(--tx)}
.top{position:sticky;top:0;z-index:10;background:var(--card);border-bottom:1px solid var(--bd);padding:10px 24px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.top h1{font-size:18px;margin:0;flex:1 1 auto;white-space:nowrap}
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
</style></head><body>
<div id="old"><b style="font-size:18px">DHCP Analyzer by Starkark98</b><br><br>
This dashboard requires a modern browser: <b>Microsoft Edge</b>, <b>Google Chrome</b> or <b>Firefox</b>.<br>
Internet Explorer is not supported. Copy this file to a PC with Edge or Chrome and open it there.</div>
<div class="top">
  <h1>DHCP Analyzer<span class="by">by Starkark98</span><small id="sub"></small><span id="demo"></span></h1>
  <input id="q" type="search" placeholder="Search IP, hostname, MAC or scope...  ( / )">
  <button id="bx">Expand all</button><button id="bc">Collapse all</button>
</div>
<main id="m"></main>
<footer id="ft"></footer>
<script>
document.getElementById('old').remove();
const D=__DATA__, WARN=80, CRIT=95;
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
const pill=s=>{const x=stInfo(s);return `<span class="pill ${x[2]}">${x[1]}</span>`};
const plural=(n,w)=>`${n} ${w}${n===1?'':'s'}`;
const fmt=n=>Number(n||0).toLocaleString('en-US');
const z=n=>n?fmt(n):'<span class="mut">0</span>';
const wday=d=>{const x=new Date(d+'T00:00:00');return isNaN(x)?'':x.toLocaleDateString('en-US',{weekday:'short'})};

/* ---------- data normalization ---------- */
D.scopes=arr(D.scopes); D.failover=arr(D.failover); D.serverOptions=arr(D.serverOptions);
const LG=D.logs||null; if(LG){['events','days','rows'].forEach(k=>LG[k]=arr(LG[k]))}
D.failover.forEach(f=>f.scopes=arr(f.scopes));
D.scopes.forEach(s=>{
  ['options','exclusions','reservations','leases'].forEach(k=>s[k]=arr(s[k]));
  if(s.scan) s.scan.ips=arr(s.scan.ips);
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
const sLbl=s=>`Scope <b>${s.id}</b>${s.name?' ('+esc(s.name)+')':''}`;
const S=D.settings||{};
if(S.authorized===false)add('crit','Server is not authorized in Active Directory');
if(!D.failover.length)add('warn','No failover configured: the DHCP server is a single point of failure');
D.failover.forEach(f=>{if(f.state!=='Normal')add('crit',`Failover <b>${esc(f.name)}</b> is in state ${esc(f.state)}`)});
if(S.auditOn===false)add('warn','DHCP audit log is disabled');
if(S.dnsDyn&&S.dnsDyn!=='Never'&&!S.dnsCred)add('warn','Dynamic DNS updates are enabled without dedicated DNS credentials (not recommended, especially when DHCP runs on a domain controller)');
D.scopes.forEach(s=>{
  const L=`Scope <b>${s.id}</b>${s.name?' ('+esc(s.name)+')':''}`;
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
function sec(id,title,b,body,open){return `<section class="sec${open?' open':''}" id="${id}"><h2 onclick="this.parentNode.classList.toggle('open')">${title} ${b||''}</h2><div class="body">${body}</div></section>`}
function chips(id,items){return `<div class="chips" data-for="${id}">${items.map((it,i)=>`<button data-f="${it[0]}" class="${i?'':'on'}">${it[1]} ${badge(it[2])}</button>`).join('')}</div>`}
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
const optTxt=o=>o?esc(o.value)+(o.inherited?' <span class="mut" title="Inherited from server options">(srv)</span>':''):'<span class="tcrit">missing</span>';

function mapHtml(sc,wide){
  if(sc.skipped)return '<div class="mut">Exclusion too large (over 1024 IPs): scan skipped.</div>';
  const c={occ:0,chk:0,free:0}; sc.ips.forEach(x=>c[x.cls]++);
  const tiles=sc.ips.map(x=>{const tip=[x.ip,x.ping!==''&&x.ping!=null?'Ping: '+x.ping+' ms':'',x.tcp?'TCP: '+x.tcp:'',x.mac?'MAC: '+x.mac:'',x.dns?'DNS: '+x.dns:'',x.resv?'Reservation: '+x.resv:''].filter(Boolean).join('\n');
    const nm=x.resv||String(x.dns||'').split('.')[0];
    return `<div class="t ${x.cls}" title="${esc(tip)}"><b>.${x.ip.split('.').slice(wide?2:3).join('.')}</b><span>${esc(nm)}</span></div>`}).join('');
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
  $('#sct').innerHTML=L.map(s=>{const c=pctCls(s.pct);return `<tr class="sc${s.active?'':' off'}" data-id="${s.id}">
    <td><span class="dot ${s.sev}" title="${s.sev==='ok'?'No issues':SEVL[s.sev]}"></span></td>
    <td><b>${s.id}</b>${s.active?'':' <span class="pill">inactive</span>'}<div class="mut">${esc(s.name)}</div></td>
    <td>${s.start} &ndash; ${s.end}<div class="mut">/${maskLen(s.mask)} &middot; lease ${esc(s.lease)}</div></td>
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
  const T=[['ov','Overview'],['lease',`Leases (${s.leases.length})`],['res',`Reservations (${s.reservations.length})`],['exc',`Exclusions (${s.exclusions.length})`]];
  el.innerHTML=`<div class="tabs">${T.map(t=>`<button data-tab="${t[0]}">${t[1]}</button>`).join('')}</div><div class="tab"></div>`;
  el.querySelector('.tabs').onclick=e=>{const b=e.target.closest('button');if(b){e.stopPropagation();showTab(el,s,b.dataset.tab)}};
  showTab(el,s,tab);
}
function showTab(el,s,t){
  el.querySelectorAll('.tabs button').forEach(b=>b.classList.toggle('on',b.dataset.tab===t));
  const T=el.querySelector('.tab');
  if(t==='ov'){
    T.innerHTML=`<div class="kv">${kv('Range',s.start+' &ndash; '+s.end)}${kv('Subnet mask',s.mask+' (/'+maskLen(s.mask)+')')}${kv('Lease duration',esc(s.lease))}${kv('Distributable pool',plural(s.pool,'IP')+' ('+s.free+' free)')}${kv('Failover',s.failover?esc(s.failover):'None')}${s.desc?kv('Description',esc(s.desc)):''}</div>
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
  }else{
    T.innerHTML=(s.exclusions.length?`<div class="kv">${s.exclusions.map(e=>kv(e.start+' &ndash; '+e.end,plural(e.count,'IP'))).join('')}</div>`:'<div class="mut">No exclusions</div>')
      +(s.scan?'<h3>Real usage of excluded IPs</h3>'+mapHtml(s.scan,maskLen(s.mask)<24):(s.exclusions.length?`<div class="mut hint">${D.scanned?'Scan not performed (scope inactive).':'Exclusion scan was not requested.'}</div>`:''));
  }
}
function openScope(id,tab){
  $('#scope').classList.add('open');
  let tr=document.querySelector(`tr.sc[data-id="${id}"]`);
  if(!tr){document.querySelectorAll('[data-for="scf"] button').forEach(b=>b.classList.toggle('on',b.dataset.f==='all'));renderScopes('all');tr=document.querySelector(`tr.sc[data-id="${id}"]`)}
  if(!tr)return;
  toggleScope(tr,tab||'ov');tr.scrollIntoView({behavior:'smooth',block:'start'});
  tr.classList.add('flash');setTimeout(()=>tr.classList.remove('flash'),1500);
}

/* ---------- issues list ---------- */
function renderIssues(f){
  const L=I.filter(i=>f==='all'||i.sev===f).sort((a,b)=>SEV[a.sev]-SEV[b.sev]);
  $('#isl').innerHTML=L.length?L.map(i=>`<div class="iss ${i.sev}${i.scope?' lnk" data-scope="'+i.scope+'"':i.go?' lnk" data-go="'+i.go+'"':'"'}><span class="pill ${i.sev}">${SEVL[i.sev]}</span><span>${i.text}</span>${i.scope?'<span class="go">Open scope &rsaquo;</span>':i.go?'<span class="go">Open &rsaquo;</span>':''}</div>`).join('')
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
  makeGrid(R.querySelector('.gg'),[{k:'t',t:'Type'},{k:'ip',t:'IP',sv:r=>ipN(r.ip)},{k:'n',t:'Host / Name'},{k:'mac',t:'MAC'},{k:'sc',t:'Scope',sv:r=>ipN(r.sc)},{k:'st',t:'State',f:r=>r.st?pill(r.st):''},{k:'go',t:'',f:r=>`<button data-scope="${r.sc}" data-tab="${r.tab}">Open &rsaquo;</button>`}],
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
    <td>${f.scopes.map(x=>`<a data-scope="${x}">${x}</a>`).join(', ')}</td></tr>`).join('')}</tbody></table></div>`
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
  <h3>Server options</h3>${D.serverOptions.length?`<div class="kv">${D.serverOptions.map(o=>kv(pad(o.id)+' '+esc(o.name),esc(o.value))).join('')}</div>`:'<div class="mut">No server-level options</div>'}`,false);

$('#m').innerHTML=h;
renderIssues('all');renderScopes('all');
if(LG&&$('#lgr'))makeGrid($('#lgr'),[{k:'time',t:'Time'},{k:'id',t:'Event',sv:r=>r.id,f:r=>{const a=AUD[r.id]||[r.id,'mut'];return `<span class="pill ${a[1]}">${a[0]}</span>`}},{k:'ip',t:'IP',sv:r=>ipN(r.ip)},
  {k:'scope',t:'Scope',sv:r=>ipN(r.scope),f:r=>r.scope?`<a data-scope="${r.scope}">${r.scope}</a>`:''},{k:'host',t:'Host'},{k:'mac',t:'MAC'},{k:'desc',t:'Description'}],LG.rows,{empty:'No problems in the last 7 days'});
if(LG&&$('#lge'))makeGrid($('#lge'),[{k:'level',t:'Level',sv:r=>r.level,f:r=>{const l=LVL[r.level]||['Info','mut'];return `<span class="pill ${l[1]}">${l[0]}</span>`}},{k:'log',t:'Log'},{k:'id',t:'Event ID',sv:r=>r.id,num:1},
  {k:'count',t:'Count',sv:r=>r.count,num:1},{k:'first',t:'First'},{k:'last',t:'Last'},{k:'msg',t:'Message'}],LG.events,{empty:'No errors or warnings in the last 7 days'});

/* ---------- interactions ---------- */
document.addEventListener('click',e=>{
  let t;
  if((t=e.target.closest('[data-scope]'))){openScope(t.dataset.scope,t.dataset.tab);return}
  if((t=e.target.closest('[data-go]'))){const s=document.getElementById(t.dataset.go);s.classList.add('open');s.scrollIntoView({behavior:'smooth',block:'start'});return}
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
#  REPORT OUTPUT
# =============================================================================
# '<' only occurs inside JSON strings: < keeps hostnames like "</script>" or "<!--" from breaking the page
function Build-Html([string]$json) { $Template.Replace('__DATA__', $json.Replace('<', '<')) }
function Save-Report([string]$json, [string]$server, [string]$path) {
    if ($path) {
        $path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($path)
        $dir  = Split-Path $path -Parent
        if ($dir -and -not (Test-Path $dir)) { [void](New-Item $dir -ItemType Directory -Force) }
    }
    else { $path = Join-Path $env:TEMP ("DhcpReport_{0}_{1}.html" -f ($server -replace '[^\w.-]', '_'), (Get-Date -Format yyyyMMdd_HHmmss)) }
    [IO.File]::WriteAllText($path, (Build-Html $json), [Text.UTF8Encoding]::new($false))
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
$NoBrowserMsg = "Report created, but no modern browser (Edge, Chrome or Firefox) was found on this PC: Internet Explorer cannot display the dashboard. Use 'Save as' or 'Show in folder' and open the file on a PC with Edge or Chrome, or run DHCP Analyzer from your workstation with the RSAT DHCP tools."

# =============================================================================
#  DEMO AND COMMAND-LINE MODES
# =============================================================================
if ($Demo) {
    try {
        $path = Save-Report ((New-DemoData) | ConvertTo-Json -Depth 8 -Compress) 'DEMO' $OutHtml
        Write-Host "Demo dashboard: $path" -ForegroundColor Green
        if ($NoOpen) { return }
        if (-not (Open-Report $path)) {
            try { Start-Process explorer.exe "/select,`"$path`"" } catch { }
            Show-Message "The demo dashboard was created, but no modern browser (Edge, Chrome or Firefox) was found on this PC. Internet Explorer cannot display it.`n`nThe file is now selected in File Explorer: copy it to a PC with Edge or Chrome and open it there.`n`n$path"
        }
    } catch { Show-Message "The demo could not be created:`n$($_.Exception.Message)" 'Error' }
    return
}

if ($NoGui) {
    while (-not $DhcpServer) { $DhcpServer = (Read-Host 'DHCP server name').Trim() }
    $sync = [hashtable]::Synchronized(@{ Status = ''; Progress = 0; Done = $false; Error = $null; Json = $null })
    Write-Host "Analyzing $DhcpServer..." -ForegroundColor Cyan
    & $Collector $DhcpServer (-not $SkipExclusionScan) $sync
    if ($sync.Error) { Write-Error $sync.Error; return }
    $path = Save-Report $sync.Json $DhcpServer $OutHtml
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
# Resolved now: the elevated process starts in System32, where a relative path would point somewhere else
if ($OutHtml) { $OutHtml = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutHtml); $relArgs += " -OutHtml `"$OutHtml`"" }
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
        Title="DHCP Analyzer - by Starkark98" Width="540" SizeToContent="Height" WindowStartupLocation="CenterScreen"
        ResizeMode="CanMinimize" Background="#F4F5F7" FontFamily="Segoe UI" FontSize="13">
  <Border Margin="16" Padding="24" Background="White" CornerRadius="10">
    <StackPanel>
      <StackPanel Orientation="Horizontal">
        <TextBlock Text="DHCP Analyzer" FontSize="24" FontWeight="SemiBold" Foreground="#1F2328"/>
        <TextBlock Text="by Starkark98" FontSize="13" FontStyle="Italic" Foreground="#2563EB" VerticalAlignment="Bottom" Margin="8,0,0,5"/>
        <TextBlock x:Name="TxtVer" FontSize="11" Foreground="#9CA3AF" VerticalAlignment="Bottom" Margin="8,0,0,6"/>
      </StackPanel>
      <TextBlock Text="Read-only health check of scopes, leases, reservations, exclusions, failover and server settings."
                 Foreground="#6B7280" TextWrapping="Wrap" Margin="0,4,0,20"/>
      <TextBlock Text="DHCP server" FontWeight="SemiBold" Foreground="#1F2328"/>
      <ComboBox x:Name="CmbServer" IsEditable="True" FontSize="15" Padding="6" Margin="0,6,0,14"/>
      <CheckBox x:Name="ChkScan" IsChecked="True" Foreground="#1F2328">
        <TextBlock TextWrapping="Wrap">Check real usage of excluded IPs (ping, ports, ARP, DNS)</TextBlock>
      </CheckBox>
      <TextBlock Text="Takes a few extra minutes. ARP works only for subnets this PC is connected to."
                 Foreground="#6B7280" FontSize="12" TextWrapping="Wrap" Margin="22,2,0,0"/>
      <Button x:Name="BtnRun" Content="Analyze" Height="40" Margin="0,22,0,0" FontSize="15" FontWeight="SemiBold"
              IsDefault="True" Background="#2563EB" Foreground="White" BorderThickness="0" Cursor="Hand"/>
      <Button x:Name="BtnDemo" Content="No server at hand? Try the demo with sample data" Margin="0,10,0,0" Padding="0,4"
              Background="Transparent" BorderThickness="0" Foreground="#2563EB" Cursor="Hand" HorizontalAlignment="Center"/>
      <ProgressBar x:Name="Bar" Height="8" Margin="0,14,0,0" Minimum="0" Maximum="100" Visibility="Collapsed" Foreground="#2563EB"/>
      <TextBox x:Name="TxtStatus" Margin="0,8,0,0" Foreground="#4B5563" TextWrapping="Wrap" IsReadOnly="True"
               BorderThickness="0" Background="Transparent" Padding="0"/>
      <WrapPanel x:Name="PnlDone" Margin="0,14,0,0" Visibility="Collapsed">
        <Button x:Name="BtnOpen" Content="Open dashboard" Padding="14,6" Margin="0,0,8,0" Cursor="Hand"/>
        <Button x:Name="BtnSave" Content="Save as..." Padding="14,6" Margin="0,0,8,0" Cursor="Hand"/>
        <Button x:Name="BtnFolder" Content="Show in folder" Padding="14,6" Cursor="Hand"/>
      </WrapPanel>
    </StackPanel>
  </Border>
</Window>
'@

try { $win = [Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($xaml)) }
catch { Show-Message "DHCP Analyzer could not open its window:`n$($_.Exception.Message)" 'Error'; return }
$ui  = @{}
'CmbServer', 'ChkScan', 'BtnRun', 'BtnDemo', 'Bar', 'TxtStatus', 'PnlDone', 'BtnOpen', 'BtnSave', 'BtnFolder', 'TxtVer' | ForEach-Object { $ui[$_] = $win.FindName($_) }
$ui.TxtVer.Text = "v$AppVersion"

$cfgDir   = Join-Path $env:APPDATA 'DhcpAnalyzer'
$lastFile = Join-Path $cfgDir 'last.txt'
$script:report = $null; $script:job = $null

function Set-Status([string]$text, [bool]$isError = $false) {
    $ui.TxtStatus.Text = $text
    $ui.TxtStatus.Foreground = if ($isError) { [Windows.Media.Brushes]::Firebrick } else { [Windows.Media.Brushes]::DimGray }
}
function Set-Busy([bool]$busy) {
    $ui.CmbServer.IsEnabled = -not $busy; $ui.ChkScan.IsEnabled = -not $busy
    $ui.BtnRun.IsEnabled = -not $busy; $ui.BtnDemo.IsEnabled = -not $busy
    $ui.Bar.Visibility = if ($busy) { 'Visible' } else { 'Collapsed' }
    if ($busy) { $ui.PnlDone.Visibility = 'Collapsed'; $ui.Bar.Value = 0 }
}
function Show-Report([string]$okText) {
    $ui.PnlDone.Visibility = 'Visible'
    if (Open-Report $script:report) { Set-Status $okText } else { Set-Status $NoBrowserMsg $true }
}

# Authorized DHCP servers from AD + last server used
$win.Add_ContentRendered({
    try { Import-Module DhcpServer -ErrorAction Stop; Get-DhcpServerInDC | Sort-Object DnsName | ForEach-Object { [void]$ui.CmbServer.Items.Add($_.DnsName) } }
    catch { if (-not (Get-Module -ListAvailable DhcpServer)) { Set-Status 'DhcpServer module not found: install the RSAT "DHCP Server Tools" to analyze a server. The demo works anyway.' $true } }
})
if ($DhcpServer) { $ui.CmbServer.Text = $DhcpServer }
elseif (Test-Path $lastFile) { try { $ui.CmbServer.Text = "$(Get-Content $lastFile -Raw)".Trim() } catch { } }
if ($SkipExclusionScan) { $ui.ChkScan.IsChecked = $false }

$timer = [Windows.Threading.DispatcherTimer]::new()
$timer.Interval = [TimeSpan]::FromMilliseconds(250)
$timer.Add_Tick({
    try {
        $ui.Bar.Value = $script:sync.Progress
        if ($script:sync.Status) { Set-Status $script:sync.Status }
        if (-not $script:sync.Done) { return }
        $timer.Stop()
        try { [void]$script:job.EndInvoke($script:handle) } catch { }
        $script:job.Dispose(); $script:job = $null
        Set-Busy $false
        if ($script:sync.Error) { Set-Status "Error: $($script:sync.Error)" $true; return }
        $script:report = Save-Report $script:sync.Json $script:srv $OutHtml
        Show-Report 'Analysis completed. Dashboard opened in your browser.'
    } catch { $timer.Stop(); Set-Busy $false; Set-Status "Error: $($_.Exception.Message)" $true }
})

$ui.BtnRun.Add_Click({
    try {
        $srv = "$($ui.CmbServer.Text)".Trim()
        if (-not $srv) { Set-Status 'Enter the DHCP server name.' $true; return }
        try { if (-not (Test-Path $cfgDir)) { [void](New-Item $cfgDir -ItemType Directory) }; Set-Content $lastFile $srv } catch { }
        Set-Busy $true
        $script:srv    = $srv
        $script:sync   = [hashtable]::Synchronized(@{ Status = 'Starting analysis...'; Progress = 0; Done = $false; Error = $null; Json = $null })
        $script:job    = [powershell]::Create()
        [void]$script:job.AddScript($Collector.ToString()).AddArgument($srv).AddArgument([bool]$ui.ChkScan.IsChecked).AddArgument($script:sync)
        $script:handle = $script:job.BeginInvoke()
        $timer.Start()
    } catch { Set-Busy $false; Set-Status "Error: $($_.Exception.Message)" $true }
})
$ui.BtnDemo.Add_Click({
    try {
        $script:report = Save-Report ((New-DemoData) | ConvertTo-Json -Depth 8 -Compress) 'DEMO' $null
        Show-Report 'Demo dashboard opened in your browser (fictitious data).'
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
$win.Add_Closing({ if ($script:job) { try { $script:job.Stop(); $script:job.Dispose() } catch { } } })

[void]$win.ShowDialog()
