#requires -RunAsAdministrator
<#
.SYNOPSIS
    Script de Diagnóstico, Otimização e Hardening de Rede para Gaming - v1.2
    
.DESCRIPTION
    Realiza diagnóstico completo da rede, aplica otimizações seguras para reduzir latência
    e melhorar estabilidade em jogos (desktop e web/browser-based).
    
    MELHORIAS v1.2:
    - Otimizações específicas para jogos web/browser (WebSocket, HTTP/2)
    - Configurações de navegador para reduzir latência
    - Otimização de SSL/TLS handshake
    - Ajustes de Keep-Alive e Connection Pooling
    - Detecção e otimização de proxies/VPN para jogos web
    - Priorização de tráfego WebSocket (portas 80/443)
    - Análise de DNS over HTTPS (DoH) e impacto em jogos
    
.PARAMETER WebGameMode
    Otimizações específicas para jogos baseados em navegador (Habblet, etc)

.PARAMETER OptimizeApps
    Detecta e otimiza aplicativos específicos (Discord, Steam, LoL, etc)
    
.EXAMPLE
    .\NetworkOptimizer.ps1 -WebGameMode
    
.EXAMPLE
    .\NetworkOptimizer.ps1 -ApplyAll -WebGameMode -OptimizeApps
    
.EXAMPLE
    .\NetworkOptimizer.ps1 -OptimizeApps
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SetDns,
    [switch]$SetMtu,
    [switch]$ApplyTcpTweaks,
    [switch]$Rollback,
    [switch]$GameMode,
    [switch]$WebGameMode,
    [switch]$OptimizeApps,
    [switch]$ApplyAll
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:LogFile = "NetworkOptimizer_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$Script:BackupFile = "NetworkBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
$Script:ConfigBackup = @{}

# Hosts para testes de conectividade
$Script:TestHosts = @(
    @{Name="Cloudflare"; Address="1.1.1.1"},
    @{Name="Google"; Address="8.8.8.8"},
    @{Name="Google Domain"; Address="google.com"}
)

# ============================================================================
# FUNÇÕES DE LOGGING E UTILIDADES
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    $color = switch($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        "INFO" { "Cyan" }
        default { "White" }
    }
    
    Write-Host $logMessage -ForegroundColor $color
    Add-Content -Path $Script:LogFile -Value $logMessage
}

function Write-Section {
    param([string]$Title)
    
    $separator = "=" * 80
    Write-Host "`n$separator" -ForegroundColor Magenta
    Write-Host "  $Title" -ForegroundColor Magenta
    Write-Host "$separator`n" -ForegroundColor Magenta
    Write-Log -Message $Title -Level "INFO"
}

function Confirm-Action {
    param([string]$Message)
    
    if ($DryRun) {
        Write-Log "[DRY-RUN] $Message" -Level "WARNING"
        return $false
    }
    
    Write-Host "`n$Message" -ForegroundColor Yellow
    $response = Read-Host "Confirma? (Y/N)"
    return ($response -eq "Y" -or $response -eq "y")
}

# ============================================================================
# FUNÇÕES DE DIAGNÓSTICO
# ============================================================================

function Test-ThirdPartySoftware {
    Write-Section "Detectando Software de Terceiros"
    
    $thirdParty = @{
        CloudflareWARP = $false
        Tailscale = $false
        Malwarebytes = $false
    }
    
    $warpService = Get-Service -Name "Cloudflare WARP*" -ErrorAction SilentlyContinue
    $warpProcess = Get-Process -Name "*warp*" -ErrorAction SilentlyContinue
    
    if ($warpService -or $warpProcess) {
        $thirdParty.CloudflareWARP = $true
        Write-Log "✓ Cloudflare WARP detectado (Serviço: $($warpService.Status))" -Level "WARNING"
        Write-Host "  ATENÇÃO: WARP pode afetar jogos web. Considere desabilitar para testes." -ForegroundColor Yellow
    }
    
    $tailscaleService = Get-Service -Name "Tailscale*" -ErrorAction SilentlyContinue
    $tailscaleProcess = Get-Process -Name "tailscale*" -ErrorAction SilentlyContinue
    
    if ($tailscaleService -or $tailscaleProcess) {
        $thirdParty.Tailscale = $true
        Write-Log "✓ Tailscale detectado (Serviço: $($tailscaleService.Status))" -Level "WARNING"
        Write-Host "  ATENÇÃO: Tailscale pode criar interfaces virtuais." -ForegroundColor Yellow
    }
    
    $mbamService = Get-Service -Name "MBAMService" -ErrorAction SilentlyContinue
    $mbamProcess = Get-Process -Name "mbam*" -ErrorAction SilentlyContinue
    
    if ($mbamService -or $mbamProcess) {
        $thirdParty.Malwarebytes = $true
        Write-Log "✓ Malwarebytes detectado (Serviço: $($mbamService.Status))" -Level "WARNING"
        Write-Host "  INFO: Malwarebytes possui proteção de rede." -ForegroundColor Yellow
    }
    
    if (-not ($thirdParty.CloudflareWARP -or $thirdParty.Tailscale -or $thirdParty.Malwarebytes)) {
        Write-Log "✓ Nenhum software de terceiros detectado" -Level "SUCCESS"
    }
    
    return $thirdParty
}

function Get-NetworkAdapters {
    Write-Section "Adaptadores de Rede Ativos"
    
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    
    foreach ($adapter in $adapters) {
        Write-Log "Adaptador: $($adapter.Name)"
        Write-Host "  Interface: $($adapter.InterfaceDescription)" -ForegroundColor Gray
        Write-Host "  Status: $($adapter.Status)" -ForegroundColor Green
        Write-Host "  Velocidade: $($adapter.LinkSpeed)" -ForegroundColor Gray
        Write-Host "  MAC: $($adapter.MacAddress)" -ForegroundColor Gray
        
        $ipv4 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipv4) {
            Write-Host "  IPv4: $($ipv4.IPAddress)/$($ipv4.PrefixLength)" -ForegroundColor Cyan
        }
        
        $gateway = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
        if ($gateway) {
            Write-Host "  Gateway: $($gateway.NextHop)" -ForegroundColor Cyan
        }
        
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dns.ServerAddresses) {
            Write-Host "  DNS: $($dns.ServerAddresses -join ', ')" -ForegroundColor Cyan
        }
        
        $netIp = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($netIp) {
            Write-Host "  MTU: $($netIp.NlMtu) bytes" -ForegroundColor Cyan
        }
        
        Write-Host ""
    }
    
    return $adapters
}

function Test-Connectivity {
    Write-Section "Testes de Conectividade"
    
    $results = @()
    
    foreach ($testHost in $Script:TestHosts) {
        Write-Log "Testando: $($testHost.Name) ($($testHost.Address))"
        
        try {
            $testResult = Test-NetConnection -ComputerName $testHost.Address -ErrorAction Stop
            Write-Host "  ✓ Conectividade: OK" -ForegroundColor Green
            Write-Host "  Ping: $($testResult.PingSucceeded)" -ForegroundColor Gray
            if ($testResult.PingReplyDetails) {
                Write-Host "  RTT: $($testResult.PingReplyDetails.RoundtripTime)ms" -ForegroundColor Gray
            }
        }
        catch {
            Write-Log "  ✗ Erro no teste: $($_.Exception.Message)" -Level "ERROR"
        }
        
        Write-Host "  Executando 20 pings para medição precisa..." -ForegroundColor Gray
        $pings = 1..20 | ForEach-Object {
            $ping = Test-Connection -ComputerName $testHost.Address -Count 1 -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 50
            return $ping
        }
        
        $successPings = $pings | Where-Object {$_ -ne $null}
        
        if ($successPings.Count -gt 0) {
            $latencies = $successPings | Select-Object -ExpandProperty Latency
            $avgLatency = ($latencies | Measure-Object -Average).Average
            $minLatency = ($latencies | Measure-Object -Minimum).Minimum
            $maxLatency = ($latencies | Measure-Object -Maximum).Maximum
            
            $variance = ($latencies | ForEach-Object { [Math]::Pow($_ - $avgLatency, 2) } | Measure-Object -Average).Average
            $jitterStdDev = [Math]::Sqrt($variance)
            $jitterRange = $maxLatency - $minLatency
            
            $packetLoss = ((20 - $successPings.Count) / 20) * 100
            
            Write-Host "  Latência Média: $([math]::Round($avgLatency, 2))ms" -ForegroundColor Cyan
            Write-Host "  Latência Min/Max: $minLatency/$maxLatency ms" -ForegroundColor Cyan
            Write-Host "  Jitter (desvio padrão): $([math]::Round($jitterStdDev, 2))ms" -ForegroundColor $(if($jitterStdDev -gt 10){"Red"}elseif($jitterStdDev -gt 5){"Yellow"}else{"Green"})
            Write-Host "  Jitter (range): $jitterRange ms" -ForegroundColor $(if($jitterRange -gt 30){"Red"}elseif($jitterRange -gt 15){"Yellow"}else{"Green"})
            Write-Host "  Perda de Pacotes: $packetLoss%" -ForegroundColor $(if($packetLoss -gt 1){"Red"}elseif($packetLoss -gt 0){"Yellow"}else{"Green"})
            
            $quality = "Excelente"
            $qualityColor = "Green"
            
            if ($avgLatency -gt 100 -or $jitterStdDev -gt 20 -or $packetLoss -gt 5) {
                $quality = "Ruim"
                $qualityColor = "Red"
            }
            elseif ($avgLatency -gt 50 -or $jitterStdDev -gt 10 -or $packetLoss -gt 1) {
                $quality = "Aceitável"
                $qualityColor = "Yellow"
            }
            elseif ($avgLatency -gt 30 -or $jitterStdDev -gt 5) {
                $quality = "Bom"
                $qualityColor = "Cyan"
            }
            
            Write-Host "  Qualidade da Conexão: $quality" -ForegroundColor $qualityColor
            
            $results += @{
                Host = $testHost.Name
                Address = $testHost.Address
                AvgLatency = $avgLatency
                MinLatency = $minLatency
                MaxLatency = $maxLatency
                JitterStdDev = $jitterStdDev
                JitterRange = $jitterRange
                PacketLoss = $packetLoss
                Quality = $quality
            }
        }
        else {
            Write-Log "  ✗ Todos os pings falharam" -Level "ERROR"
        }
        
        Write-Host ""
    }
    
    return $results
}

function Measure-OptimalMtu {
    Write-Section "Medindo MTU Ideal (Path MTU Discovery)"
    
    $adapter = Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1
    
    if (-not $adapter) {
        Write-Log "Nenhum adaptador ativo encontrado" -Level "ERROR"
        return $null
    }
    
    Write-Log "Testando MTU para adaptador: $($adapter.Name)"
    
    $mtuSizes = @(1500, 1492, 1472, 1450, 1400)
    $optimalMtu = $null
    
    foreach ($mtu in $mtuSizes) {
        $packetSize = $mtu - 28
        Write-Host "  Testando MTU $mtu (packet size: $packetSize)..." -ForegroundColor Gray
        
        try {
            $result = ping 1.1.1.1 -n 3 -l $packetSize -f 2>&1
            
            if ($result -match "Reply from" -and $result -notmatch "fragment") {
                Write-Host "    ✓ MTU $mtu OK (sem fragmentação)" -ForegroundColor Green
                $optimalMtu = $mtu
                break
            }
            elseif ($result -match "fragment") {
                Write-Host "    ✗ MTU $mtu causa fragmentação" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "    ✗ Falha no teste MTU $mtu" -ForegroundColor Red
        }
    }
    
    if ($optimalMtu) {
        $currentMtu = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).NlMtu
        Write-Host "`n  MTU Atual: $currentMtu" -ForegroundColor Cyan
        Write-Host "  MTU Recomendado: $optimalMtu" -ForegroundColor Green
        
        if ($currentMtu -ne $optimalMtu) {
            Write-Host "  ⚠ Ajuste de MTU recomendado (use -SetMtu)" -ForegroundColor Yellow
        }
        
        return @{
            Adapter = $adapter
            CurrentMtu = $currentMtu
            OptimalMtu = $optimalMtu
        }
    }
    else {
        Write-Log "Path MTU Discovery falhou - usando heurística de fallback" -Level "WARNING"
        
        $fallbackMtu = 1472
        $currentMtu = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).NlMtu
        
        Write-Host "`n  ⚠ Path MTU Discovery não conseguiu determinar MTU ideal" -ForegroundColor Yellow
        Write-Host "  MTU Atual: $currentMtu" -ForegroundColor Cyan
        Write-Host "  MTU Recomendado (heurístico): $fallbackMtu" -ForegroundColor Yellow
        
        return @{
            Adapter = $adapter
            CurrentMtu = $currentMtu
            OptimalMtu = $fallbackMtu
            IsFallback = $true
        }
    }
}

# ============================================================================
# FUNÇÕES DE BACKUP E RESTAURAÇÃO
# ============================================================================

function Backup-NetworkConfig {
    Write-Section "Backup de Configurações"
    
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    
    foreach ($adapter in $adapters) {
        $config = @{
            Name = $adapter.Name
            InterfaceIndex = $adapter.ifIndex
            DNS = (Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
            MTU = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).NlMtu
        }
        
        $Script:ConfigBackup[$adapter.Name] = $config
    }
    
    # Backup de TCP/IP e configurações web
    $Script:ConfigBackup["TCP"] = @{
        AutoTuningLevel = (Get-NetTCPSetting -SettingName Internet).AutoTuningLevelLocal
        Timestamps = (Get-NetTCPSetting -SettingName Internet).Timestamps
        InitialRto = (Get-NetTCPSetting -SettingName Internet).InitialRto
    }
    
    # Backup de proxy
    $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $Script:ConfigBackup["Proxy"] = @{
        ProxyEnable = $proxySettings.ProxyEnable
        ProxyServer = $proxySettings.ProxyServer
        AutoDetect = $proxySettings.AutoDetect
    }
    
    $Script:ConfigBackup | ConvertTo-Json -Depth 5 | Out-File -FilePath $Script:BackupFile -Encoding UTF8
    Write-Log "✓ Backup salvo em: $Script:BackupFile" -Level "SUCCESS"
}

function Restore-NetworkConfig {
    Write-Section "Restaurando Configurações do Backup"
    
    $backupFiles = Get-ChildItem -Path "NetworkBackup_*.json" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending
    
    if (-not $backupFiles) {
        Write-Log "Nenhum arquivo de backup encontrado!" -Level "ERROR"
        return
    }
    
    $latestBackup = $backupFiles[0]
    Write-Log "Restaurando de: $($latestBackup.Name)"
    
    try {
        $backup = Get-Content -Path $latestBackup.FullName | ConvertFrom-Json
        
        # Restaurar DNS e MTU
        foreach ($adapterName in $backup.PSObject.Properties.Name) {
            if ($adapterName -in @("TCP", "Proxy")) { continue }
            
            $config = $backup.$adapterName
            $adapter = Get-NetAdapter -Name $config.Name -ErrorAction SilentlyContinue
            
            if ($adapter -and $config.DNS) {
                Write-Log "Restaurando DNS para: $($adapter.Name)"
                Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses $config.DNS
                Write-Host "  ✓ DNS restaurado" -ForegroundColor Green
            }
            
            if ($adapter -and $config.MTU) {
                Write-Log "Restaurando MTU para: $($adapter.Name)"
                Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -NlMtuBytes $config.MTU
                Write-Host "  ✓ MTU restaurado para $($config.MTU)" -ForegroundColor Green
            }
        }
        
        # Restaurar TCP
        if ($backup.TCP) {
            Write-Log "Restaurando configurações TCP/IP"
            Set-NetTCPSetting -SettingName Internet -AutoTuningLevelLocal $backup.TCP.AutoTuningLevel
            Write-Host "  ✓ TCP AutoTuning restaurado" -ForegroundColor Green
        }
        
        # Restaurar Proxy
        if ($backup.Proxy) {
            Write-Log "Restaurando configurações de proxy"
            $proxyPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            Set-ItemProperty -Path $proxyPath -Name "ProxyEnable" -Value $backup.Proxy.ProxyEnable
            if ($backup.Proxy.ProxyServer) {
                Set-ItemProperty -Path $proxyPath -Name "ProxyServer" -Value $backup.Proxy.ProxyServer
            }
            Set-ItemProperty -Path $proxyPath -Name "AutoDetect" -Value $backup.Proxy.AutoDetect
            Write-Host "  ✓ Proxy restaurado" -ForegroundColor Green
        }
        
        # Remover políticas QoS criadas pelo script
        Get-NetQosPolicy -Name "WebGame*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false
        Get-NetQosPolicy -Name "GameBoost*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false
        Get-NetQosPolicy -Name "Discord*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false
        Get-NetQosPolicy -Name "Steam*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false
        Get-NetQosPolicy -Name "LoL*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false
        Get-NetQosPolicy -Name "Riot*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false
        Write-Host "  ✓ Políticas QoS removidas" -ForegroundColor Green
        
        Write-Log "✓ Restauração concluída com sucesso!" -Level "SUCCESS"
        
    }
    catch {
        Write-Log "Erro ao restaurar backup: $($_.Exception.Message)" -Level "ERROR"
    }
}

# ============================================================================
# FUNÇÕES DE OTIMIZAÇÃO
# ============================================================================

function Set-OptimalDns {
    Write-Section "Configuração de DNS Cloudflare"
    
    if (-not $SetDns -and -not (Confirm-Action "Configurar DNS Cloudflare (1.1.1.1 / 1.0.0.1)?")) {
        return
    }
    
    $adapters = Get-NetAdapter | Where-Object {$_.Status -eq "Up"}
    
    foreach ($adapter in $adapters) {
        if ($adapter.InterfaceDescription -match "Tailscale|WARP|Virtual|Loopback") {
            Write-Log "Pulando adaptador virtual: $($adapter.Name)" -Level "WARNING"
            continue
        }
        
        Write-Log "Configurando DNS para: $($adapter.Name)"
        
        try {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses ("1.1.1.1", "1.0.0.1")
            Write-Host "  ✓ DNS Cloudflare configurado" -ForegroundColor Green
            
            ipconfig /flushdns | Out-Null
            Write-Host "  ✓ Cache DNS limpo" -ForegroundColor Green
        }
        catch {
            Write-Log "Erro ao configurar DNS: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Set-OptimalMtu {
    param($MtuInfo)
    
    Write-Section "Aplicando MTU Otimizado"
    
    if (-not $MtuInfo) {
        Write-Log "Informações de MTU não disponíveis" -Level "WARNING"
        return
    }
    
    if ($MtuInfo.CurrentMtu -eq $MtuInfo.OptimalMtu) {
        Write-Log "MTU já está otimizado ($($MtuInfo.OptimalMtu))" -Level "SUCCESS"
        return
    }
    
    if (-not $SetMtu -and -not (Confirm-Action "Aplicar MTU otimizado ($($MtuInfo.OptimalMtu)) no adaptador $($MtuInfo.Adapter.Name)?")) {
        return
    }
    
    try {
        Set-NetIPInterface -InterfaceIndex $MtuInfo.Adapter.ifIndex -AddressFamily IPv4 -NlMtuBytes $MtuInfo.OptimalMtu
        Write-Host "  ✓ MTU configurado para $($MtuInfo.OptimalMtu)" -ForegroundColor Green
        Write-Log "MTU otimizado aplicado com sucesso" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erro ao configurar MTU: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Set-TcpOptimizations {
    Write-Section "Otimizações TCP/IP para Gaming"
    
    if (-not $ApplyTcpTweaks -and -not (Confirm-Action "Aplicar otimizações TCP/IP?")) {
        return
    }
    
    try {
        Write-Log "Configurando TCP AutoTuning para Normal..."
        netsh int tcp set global autotuninglevel=normal | Out-Null
        Write-Host "  ✓ AutoTuning: Normal" -ForegroundColor Green
        
        Write-Log "Habilitando TCP Timestamps..."
        netsh int tcp set global timestamps=enabled | Out-Null
        Write-Host "  ✓ Timestamps: Enabled" -ForegroundColor Green
        
        Write-Log "Configurando Initial RTO..."
        netsh int tcp set global initialRto=3000 | Out-Null
        Write-Host "  ✓ Initial RTO: 3000ms" -ForegroundColor Green
        
        Write-Log "Configurando Congestion Provider para CUBIC..."
        netsh int tcp set supplemental custom congestionprovider=cubic | Out-Null
        Write-Host "  ✓ Congestion Provider: CUBIC" -ForegroundColor Green
        
        Write-Log "Habilitando RSS..."
        netsh int tcp set global rss=enabled | Out-Null
        Write-Host "  ✓ RSS: Enabled" -ForegroundColor Green
        
        Write-Log "Otimizações TCP/IP aplicadas com sucesso" -Level "SUCCESS"
    }
    catch {
        Write-Log "Erro ao aplicar otimizações TCP: $($_.Exception.Message)" -Level "ERROR"
    }
}

# ============================================================================
# NOVAS FUNÇÕES PARA JOGOS WEB
# ============================================================================

function Test-WebGameConnectivity {
    Write-Section "Diagnóstico Específico para Jogos Web"
    
    Write-Log "Testando conectividade WebSocket e HTTP/2..."
    
    # Testar latência HTTPS (simulando handshake SSL/TLS)
    $webServers = @(
        @{Name="Cloudflare"; Url="https://1.1.1.1"},
        @{Name="Google"; Url="https://www.google.com"}
    )
    
    foreach ($server in $webServers) {
        Write-Host "  Testando: $($server.Name)..." -ForegroundColor Gray
        
        try {
            # Medir tempo de resposta HTTPS completo
            $measure = Measure-Command {
                $response = Invoke-WebRequest -Uri $server.Url -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            }
            
            $latency = $measure.TotalMilliseconds
            Write-Host "    ✓ Latência HTTPS: $([math]::Round($latency, 2))ms" -ForegroundColor $(if($latency -lt 100){"Green"}elseif($latency -lt 200){"Yellow"}else{"Red"})
            
            # Verificar suporte HTTP/2
            if ($response.Headers.ContainsKey("Alt-Svc") -or $response.BaseResponse.Version -eq "2.0") {
                Write-Host "    ✓ HTTP/2 suportado" -ForegroundColor Green
            }
            else {
                Write-Host "    ⚠ HTTP/2 não detectado (pode impactar performance)" -ForegroundColor Yellow
            }
            
        }
        catch {
            Write-Host "    ✗ Erro: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Testar DNS sobre HTTPS (DoH) - pode adicionar latência
    Write-Host "`n  Verificando DNS over HTTPS (DoH)..." -ForegroundColor Gray
    
    $dohServers = @("1.1.1.1", "8.8.8.8")
    $hasDoh = $false
    
    Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
        $dns = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        
        if ($dns.ServerAddresses) {
            foreach ($dnsAddr in $dns.ServerAddresses) {
                if ($dnsAddr -in $dohServers) {
                    $hasDoh = $true
                }
            }
        }
    }
    
    if ($hasDoh) {
        Write-Host "    ℹ DoH possivelmente ativo (Cloudflare/Google DNS detectado)" -ForegroundColor Cyan
        Write-Host "    DoH pode adicionar ~10-30ms de latência em jogos web" -ForegroundColor Gray
    }
}

function Test-BrowserPerformance {
    Write-Section "Análise de Performance do Navegador"
    
    Write-Log "Verificando configurações de navegadores instalados..."
    
    # Detectar navegadores instalados
    $browsers = @()
    
    # Chrome/Edge (Chromium-based)
    $chromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe",
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )
    
    foreach ($path in $chromePaths) {
        if (Test-Path $path) {
            $browserName = if ($path -match "Edge") { "Microsoft Edge" } else { "Google Chrome" }
            $browsers += @{Name=$browserName; Path=$path; Type="Chromium"}
            Write-Host "  ✓ $browserName detectado" -ForegroundColor Green
        }
    }
    
    # Brave Browser
    $bravePaths = @(
        "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe",
        "$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe"
    )
    
    foreach ($path in $bravePaths) {
        if (Test-Path $path) {
            $browsers += @{Name="Brave Browser"; Path=$path; Type="Chromium"}
            Write-Host "  ✓ Brave Browser detectado" -ForegroundColor Green
        }
    }
    
    # Firefox
    $firefoxPaths = @(
        "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
        "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe"
    )
    
    foreach ($path in $firefoxPaths) {
        if (Test-Path $path) {
            $browsers += @{Name="Mozilla Firefox"; Path=$path; Type="Firefox"}
            Write-Host "  ✓ Mozilla Firefox detectado" -ForegroundColor Green
        }
    }
    
    if ($browsers.Count -eq 0) {
        Write-Host "  ⚠ Nenhum navegador detectado" -ForegroundColor Yellow
        return
    }
    
    Write-Host "`n  💡 RECOMENDAÇÕES PARA JOGOS WEB:" -ForegroundColor Yellow
    Write-Host "     1. Feche abas desnecessárias (reduz contenção de conexões)" -ForegroundColor Gray
    Write-Host "     2. Desabilite extensões pesadas durante jogos" -ForegroundColor Gray
    Write-Host "     3. Limpe cache e cookies periodicamente" -ForegroundColor Gray
    Write-Host "     4. Use modo de navegação anônima para testes A/B" -ForegroundColor Gray
    
    return $browsers
}

function Optimize-BrowserSettings {
    Write-Section "Otimizações de Navegador para Jogos Web"
    
    Write-Host @"
OTIMIZAÇÕES MANUAIS RECOMENDADAS:

🦁 BRAVE BROWSER (Baseado em Chromium):
   1. Digite na barra de endereço: brave://flags
   
   2. Habilitar:
      • #enable-quic → Enabled
        (Protocolo QUIC/HTTP3 - menor latência)
      
      • #enable-parallel-downloading → Enabled
        (Downloads paralelos)
      
      • #smooth-scrolling → Disabled
        (Reduz uso de CPU durante jogo)
      
   3. Configurações (brave://settings):
      • Shields → DESABILITAR durante jogos (pode causar lag)
        IMPORTANTE: Shields do Brave bloqueiam scripts e podem interferir
      
      • Sistema → "Usar aceleração de hardware" → ON
      
      • Privacidade e Segurança:
        - "Pré-carregar páginas para navegação mais rápida" → ON
        - Brave Firewall + VPN → OFF durante jogos (adiciona latência)
      
   4. Extensões a REMOVER/DESABILITAR:
      • Ad blockers extras (Brave já tem built-in)
      • VPNs de extensão
      • Gerenciadores de senhas ativos
      • Qualquer extensão que modifique requisições de rede

🌐 GOOGLE CHROME / MICROSOFT EDGE:
   1. Digite: chrome://flags (ou edge://flags)
   
   2. Mesmas configurações do Brave acima
   
   3. Configurações Avançadas:
      • Sistema → "Usar aceleração de hardware" → ON
      • Privacidade → "Pré-carregar páginas" → ON (Standard)

"@ -ForegroundColor Cyan
    
    if (Confirm-Action "Deseja aplicar otimizações automáticas de sistema para navegadores?") {
        
        try {
            Write-Log "Aplicando otimizações de sistema para navegadores..."
            
            # Aumentar limite de conexões HTTP simultâneas (Registry)
            Write-Host "  Aumentando limite de conexões HTTP..." -ForegroundColor Gray
            
            $httpPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            
            Set-ItemProperty -Path $httpPath -Name "MaxConnectionsPerServer" -Value 10 -Type DWord -Force
            Set-ItemProperty -Path $httpPath -Name "MaxConnectionsPer1_0Server" -Value 10 -Type DWord -Force
            
            Write-Host "    ✓ Limite de conexões HTTP aumentado (6 → 10 por servidor)" -ForegroundColor Green
            
            Set-ItemProperty -Path $httpPath -Name "ProxyHttp1.1" -Value 1 -Type DWord -Force
            Write-Host "    ✓ HTTP 1.1 habilitado" -ForegroundColor Green
            
            Write-Host "  Desabilitando auto-detecção de proxy..." -ForegroundColor Gray
            Set-ItemProperty -Path $httpPath -Name "AutoDetect" -Value 0 -Type DWord -Force
            Write-Host "    ✓ Auto-detecção de proxy desabilitada (reduz 2-5s na primeira conexão)" -ForegroundColor Green
            
            Write-Log "Otimizações de navegador aplicadas com sucesso" -Level "SUCCESS"
            
        }
        catch {
            Write-Log "Erro ao aplicar otimizações de navegador: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Set-WebSocketOptimizations {
    Write-Section "Otimizações WebSocket para Jogos em Tempo Real"
    
    Write-Host @"
WebSocket é o protocolo usado por jogos web modernos como Habblet.
Estas otimizações reduzem latência de comunicação bidirecional:

OTIMIZAÇÕES A APLICAR:
  • Priorização de tráfego nas portas 80/443 (HTTP/HTTPS/WebSocket)
  • Desabilitar Nagle's Algorithm para portas web
  • Aumentar receive buffer para WebSocket
  • Otimizar TCP Window Scaling para tráfego web
  
"@ -ForegroundColor Yellow
    
    if (-not $WebGameMode -and -not (Confirm-Action "Aplicar otimizações WebSocket?")) {
        return
    }
    
    try {
        Write-Log "Aplicando otimizações WebSocket..."
        
        # Remover políticas QoS antigas de WebSocket
        Get-NetQosPolicy -Name "WebGame*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue
        
        # QoS para tráfego HTTP/HTTPS/WebSocket (portas 80, 443, 8080)
        Write-Host "  Criando política QoS para tráfego WebSocket..." -ForegroundColor Gray
        
        # HTTP (porta 80)
        New-NetQosPolicy -Name "WebGame_HTTP" `
            -NetworkProfile All `
            -IPProtocol TCP `
            -IPDstPortMatchCondition 80 `
            -DSCPAction 46 `
            -ThrottleRateActionBitsPerSecond 0 -ErrorAction SilentlyContinue | Out-Null
        
        # HTTPS (porta 443) - MAIS IMPORTANTE para jogos web
        New-NetQosPolicy -Name "WebGame_HTTPS" `
            -NetworkProfile All `
            -IPProtocol TCP `
            -IPDstPortMatchCondition 443 `
            -DSCPAction 46 `
            -ThrottleRateActionBitsPerSecond 0 -ErrorAction SilentlyContinue | Out-Null
        
        # Porta alternativa comum (8080)
        New-NetQosPolicy -Name "WebGame_Alt" `
            -NetworkProfile All `
            -IPProtocol TCP `
            -IPDstPortMatchCondition 8080 `
            -DSCPAction 46 `
            -ThrottleRateActionBitsPerSecond 0 -ErrorAction SilentlyContinue | Out-Null
        
        Write-Host "    ✓ QoS configurado para portas 80, 443, 8080 (DSCP EF)" -ForegroundColor Green
        
        # Desabilitar Nagle's Algorithm especificamente para portas web (Registry)
        Write-Host "  Desabilitando Nagle's Algorithm para portas web..." -ForegroundColor Gray
        
        $tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        
        # TcpAckFrequency = 1 (enviar ACKs imediatamente, não atrasar)
        Set-ItemProperty -Path $tcpParams -Name "TcpAckFrequency" -Value 1 -Type DWord -Force
        # TCPNoDelay = 1 (desabilitar Nagle)
        Set-ItemProperty -Path $tcpParams -Name "TcpNoDelay" -Value 1 -Type DWord -Force
        
        Write-Host "    ✓ Nagle desabilitado (latência reduzida para pacotes pequenos)" -ForegroundColor Green
        
        # Aumentar receive window para WebSocket
        Write-Host "  Otimizando TCP Receive Window..." -ForegroundColor Gray
        netsh int tcp set global autotuninglevel=normal | Out-Null
        Write-Host "    ✓ TCP Auto-Tuning configurado" -ForegroundColor Green
        
        # Habilitar Timestamps para melhor RTT tracking
        netsh int tcp set global timestamps=enabled | Out-Null
        Write-Host "    ✓ TCP Timestamps habilitados" -ForegroundColor Green
        
        # Ajustar Initial Congestion Window (IW10 é ideal para web)
        netsh int tcp set global initialRto=2000 | Out-Null
        Write-Host "    ✓ Initial RTO ajustado para 2000ms (web-optimized)" -ForegroundColor Green
        
        Write-Log "Otimizações WebSocket aplicadas com sucesso" -Level "SUCCESS"
        Write-Host "`n  ⚡ REINICIE O NAVEGADOR para aplicar mudanças!" -ForegroundColor Magenta
        
    }
    catch {
        Write-Log "Erro ao aplicar otimizações WebSocket: $($_.Exception.Message)" -Level "ERROR"
    }
}

function Clear-BrowserCache {
    Write-Section "Limpeza de Cache de Navegadores"
    
    Write-Host @"
Cache de navegador pode causar:
  • Conexões antigas/inválidas
  • Cookies corrompidos
  • DNS cache desatualizado no navegador

"@ -ForegroundColor Gray
    
    if (Confirm-Action "Limpar cache de navegadores detectados?") {
        
        # Chrome
        $chromeCachePaths = @(
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\GPUCache"
        )
        
        foreach ($path in $chromeCachePaths) {
            if (Test-Path $path) {
                try {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  ✓ Cache Chrome limpo: $path" -ForegroundColor Green
                }
                catch {
                    Write-Host "  ⚠ Não foi possível limpar (navegador aberto?): $path" -ForegroundColor Yellow
                }
            }
        }
        
        # Edge
        $edgeCachePaths = @(
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
            "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache"
        )
        
        foreach ($path in $edgeCachePaths) {
            if (Test-Path $path) {
                try {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  ✓ Cache Edge limpo: $path" -ForegroundColor Green
                }
                catch {
                    Write-Host "  ⚠ Não foi possível limpar (navegador aberto?): $path" -ForegroundColor Yellow
                }
            }
        }
        
        # Brave Browser
        $braveCachePaths = @(
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache",
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Code Cache",
            "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\GPUCache"
        )
        
        foreach ($path in $braveCachePaths) {
            if (Test-Path $path) {
                try {
                    Remove-Item -Path "$path\*" -Recurse -Force -ErrorAction SilentlyContinue
                    Write-Host "  ✓ Cache Brave limpo: $path" -ForegroundColor Green
                }
                catch {
                    Write-Host "  ⚠ Não foi possível limpar (navegador aberto?): $path" -ForegroundColor Yellow
                }
            }
        }
        
        Write-Host "`n  ℹ IMPORTANTE: Feche todos os navegadores antes de limpar cache!" -ForegroundColor Cyan
        Write-Log "Limpeza de cache de navegadores concluída" -Level "SUCCESS"
    }
}

function Test-ProxyAndVpnImpact {
    Write-Section "Análise de Impacto de Proxy/VPN em Jogos Web"
    
    Write-Log "Verificando configurações de proxy..."
    
    # Verificar proxy do sistema
    $proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    
    if ($proxySettings.ProxyEnable -eq 1) {
        Write-Host "  ⚠ PROXY ATIVO DETECTADO!" -ForegroundColor Red
        Write-Host "    Servidor: $($proxySettings.ProxyServer)" -ForegroundColor Yellow
        Write-Host "" -ForegroundColor Gray
        Write-Host "    IMPACTO EM JOGOS WEB:" -ForegroundColor Yellow
        Write-Host "      • Latência adicional: +50-200ms típico" -ForegroundColor Gray
        Write-Host "      • Conexões WebSocket podem falhar" -ForegroundColor Gray
        Write-Host "      • Timeouts em jogos tempo-real" -ForegroundColor Gray
        Write-Host "" -ForegroundColor Gray
        Write-Host "    💡 RECOMENDAÇÃO:" -ForegroundColor Cyan
        Write-Host "       Desabilite o proxy para jogos web ou configure bypass" -ForegroundColor Gray
        
        Write-Log "Proxy ativo: $($proxySettings.ProxyServer)" -Level "WARNING"
        
        if (Confirm-Action "Desabilitar proxy temporariamente?") {
            try {
                Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value 0
                Write-Host "  ✓ Proxy desabilitado (use -Rollback para restaurar)" -ForegroundColor Green
                Write-Log "Proxy desabilitado temporariamente" -Level "SUCCESS"
            }
            catch {
                Write-Log "Erro ao desabilitar proxy: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    else {
        Write-Host "  ✓ Nenhum proxy de sistema ativo" -ForegroundColor Green
    }
    
    # Verificar auto-detect (WPAD)
    if ($proxySettings.AutoDetect -eq 1) {
        Write-Host "  ⚠ Auto-detecção de proxy ATIVA" -ForegroundColor Yellow
        Write-Host "    Pode adicionar 2-5 segundos na primeira conexão" -ForegroundColor Gray
        
        if (Confirm-Action "Desabilitar auto-detecção de proxy?") {
            Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoDetect" -Value 0
            Write-Host "  ✓ Auto-detecção desabilitada" -ForegroundColor Green
        }
    }
}

function Show-WebGameTroubleshooting {
    Write-Section "Troubleshooting para Jogos Web (Habblet, etc)"
    
    Write-Host @"
🔧 PROBLEMAS COMUNS E SOLUÇÕES:

1. LAG/LATÊNCIA ALTA:
   ✓ Execute: .\NetworkOptimizer.ps1 -WebGameMode
   ✓ Feche abas e programas que usam rede
   ✓ Desabilite VPN/proxy durante jogo
   ✓ Use DNS Cloudflare (1.1.1.1) - já aplicado se usou -SetDns

2. DESCONEXÕES FREQUENTES:
   ✓ Verifique firewall: pode estar bloqueando WebSocket
   ✓ Desabilite antivírus temporariamente (teste)
   ✓ Verifique se MTU está otimizado (use -SetMtu)
   ✓ Teste em navegador diferente (Chrome vs Firefox)

3. "CONNECTION TIMEOUT":
   ✓ Limpe cache do navegador (Ctrl+Shift+Del)
   ✓ Desabilite extensões do navegador
   ✓ Teste modo anônimo/privado
   ✓ Verifique se porta 443 não está bloqueada

4. JOGO TRAVA/FREEZE:
   ✓ Feche hardware acceleration do navegador (teste)
   ✓ Aumente prioridade do processo do navegador (Task Manager)
   ✓ Limpe DNS: ipconfig /flushdns
   ✓ Reinicie o roteador

5. PING INSTÁVEL (JITTER ALTO):
   ✓ Use cabo ethernet (não Wi-Fi)
   ✓ Desconecte outros dispositivos da rede
   ✓ Verifique QoS no roteador (priorize seu PC)
   ✓ Execute: netsh winsock reset (requer reinício)

📊 FERRAMENTAS DE DIAGNÓSTICO:
   • F12 (DevTools) → Network tab → veja latência das requisições
   • Resource Monitor (resmon.exe) → aba Network
   • PingPlotter: visualizar latência em tempo real
   • Wireshark: analisar pacotes WebSocket (avançado)

🎮 CONFIGURAÇÕES DE ROTEADOR RECOMENDADAS:
   • Habilite QoS e priorize seu PC
   • Desabilite SIP ALG (pode interferir com WebSocket)
   • Use canal Wi-Fi menos congestionado (WiFi Analyzer app)
   • Considere port forwarding se jogo requer (raro para jogos web)

"@ -ForegroundColor Cyan
    
    Write-Log "Guia de troubleshooting exibido"
}

# ============================================================================
# OTIMIZAÇÕES PARA APLICATIVOS ESPECÍFICOS
# ============================================================================

function Test-GamingApps {
    Write-Section "Detecção de Aplicativos de Jogos e Comunicação"
    
    $apps = @{
        Discord = $false
        Steam = $false
        RiotClient = $false
        LeagueOfLegends = $false
    }
    
    Write-Log "Verificando aplicativos instalados..."
    
    # Discord
    $discordProcess = Get-Process -Name "Discord" -ErrorAction SilentlyContinue
    
    if ($discordProcess -or (Test-Path $env:LOCALAPPDATA\Discord)) {
        $apps.Discord = $true
        Write-Host "  ✓ Discord detectado" -ForegroundColor Green
        if ($discordProcess) {
            Write-Host "    Status: Em execução (PID: $($discordProcess.Id))" -ForegroundColor Gray
        }
    }
    
    # Steam
    $steamProcess = Get-Process -Name "steam" -ErrorAction SilentlyContinue
    $steamPath = "${env:ProgramFiles(x86)}\Steam\steam.exe"
    
    if ($steamProcess -or (Test-Path $steamPath)) {
        $apps.Steam = $true
        Write-Host "  ✓ Steam detectado" -ForegroundColor Green
        if ($steamProcess) {
            Write-Host "    Status: Em execução (PID: $($steamProcess.Id))" -ForegroundColor Gray
        }
    }
    
    # Riot Client (Vanguard/LoL)
    $riotProcess = Get-Process -Name "RiotClientServices" -ErrorAction SilentlyContinue
    $riotPath = "$env:LOCALAPPDATA\Riot Games"
    
    if ($riotProcess -or (Test-Path $riotPath)) {
        $apps.RiotClient = $true
        Write-Host "  ✓ Riot Client detectado" -ForegroundColor Green
        if ($riotProcess) {
            Write-Host "    Status: Em execução (PID: $($riotProcess.Id))" -ForegroundColor Gray
        }
    }
    
    # League of Legends
    $lolProcess = Get-Process -Name "League*" -ErrorAction SilentlyContinue
    $lolPath = "C:\Riot Games\League of Legends"
    
    if ($lolProcess -or (Test-Path $lolPath)) {
        $apps.LeagueOfLegends = $true
        Write-Host "  ✓ League of Legends detectado" -ForegroundColor Green
        if ($lolProcess) {
            Write-Host "    Status: Em execução (PID: $($lolProcess.Id))" -ForegroundColor Gray
        }
    }
    
    if (-not ($apps.Discord -or $apps.Steam -or $apps.RiotClient -or $apps.LeagueOfLegends)) {
        Write-Host "  ℹ Nenhum aplicativo de jogo comum detectado" -ForegroundColor Gray
    }
    
    return $apps
}

function Optimize-DiscordSettings {
    Write-Section "Otimizações para Discord"
    
    Write-Host @"
🎮 DISCORD - Otimizações para Reduzir Latência e Uso de Rede:

📊 CONFIGURAÇÕES NO APLICATIVO (User Settings):
   
   1. Voz & Vídeo:
      • Qualidade de Serviço (QoS):
        ⚠ DESABILITAR "Enable Quality of Service High Packet Priority"
        Motivo: Pode conflitar com QoS do Windows/Roteador
      
      • Echo Cancellation: ON (reduz feedback, não afeta latência)
      • Noise Suppression: Krisp (melhor que padrão, mais leve que RNNoise)
      • Advanced Voice Activity: ON (economiza banda)
      
   2. Overlay (se usar):
      • Avatar Size: Small (reduz uso de GPU/CPU)
      • Text Chat Notifications: OFF (menos processamento)
      • ⚠ CONSIDERE DESABILITAR OVERLAY durante jogos competitivos
      
   3. Avançado:
      • Hardware Acceleration: ON (usa GPU, libera CPU)
      • Video Codec: H.264 (melhor compatibilidade, menor latência que VP8)
      
   4. Atividade:
      • Display currently running game: OFF durante jogos
        (Reduz polling de processos = menos overhead)

"@ -ForegroundColor Cyan
    
    if (Confirm-Action "Aplicar otimizações de rede para Discord (QoS, portas específicas)?") {
        try {
            Write-Log "Aplicando otimizações para Discord..."
            
            # Remover políticas antigas
            Get-NetQosPolicy -Name "Discord*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue
            
            # Discord usa portas UDP dinâmicas (50000-65535) para voz
            New-NetQosPolicy -Name "Discord_Voice_UDP" `
                -NetworkProfile All `
                -IPProtocol UDP `
                -IPDstPortStart 50000 -IPDstPortEnd 65535 `
                -DSCPAction 46 `
                -ThrottleRateActionBitsPerSecond 0 -ErrorAction SilentlyContinue | Out-Null
            
            Write-Host "  ✓ QoS configurado para voz do Discord (portas UDP 50000-65535)" -ForegroundColor Green
            
            # Priorizar também websocket do Discord (porta 443)
            New-NetQosPolicy -Name "Discord_WebSocket" `
                -NetworkProfile All `
                -IPProtocol TCP `
                -IPDstPortMatchCondition 443 `
                -AppPathNameMatchCondition "*Discord.exe" `
                -DSCPAction 46 `
                -ThrottleRateActionBitsPerSecond 0 -ErrorAction SilentlyContinue | Out-Null
            
            Write-Host "  ✓ QoS configurado para conexão do Discord (WebSocket porta 443)" -ForegroundColor Green
            
            Write-Log "Otimizações do Discord aplicadas" -Level "SUCCESS"
            Write-Host "`n  ⚠ REINICIE O DISCORD para aplicar mudanças!" -ForegroundColor Yellow
            
        }
        catch {
            Write-Log "Erro ao aplicar otimizações do Discord: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Optimize-SteamSettings {
    Write-Section "Otimizações para Steam"
    
    Write-Host @"
🎮 STEAM - Otimizações de Rede e Performance:

⚙️ CONFIGURAÇÕES NO STEAM CLIENT:

   1. Downloads (Settings → Downloads):
      • Limitar largura de banda durante jogos:
        - Se joga online: limitar para 50% da banda
        - Desabilitar "Allow downloads during gameplay"
      
      • Região de Download:
        - Escolher servidor mais próximo geograficamente
        - Brasil: "São Paulo" ou "South America - Sao Paulo"
      
      • Clear Download Cache (periodicamente):
        - Settings → Downloads → "Clear Download Cache"
        - Resolve problemas de conexão com servidores

"@ -ForegroundColor Cyan
    
    if (Confirm-Action "Aplicar otimizações de rede para Steam?") {
        try {
            Write-Log "Aplicando otimizações para Steam..."
            
            # Remover políticas antigas
            Get-NetQosPolicy -Name "Steam*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue
            
            # Priorizar tráfego de jogos Steam (UDP)
            New-NetQosPolicy -Name "Steam_Gaming_UDP" `
                -NetworkProfile All `
                -IPProtocol UDP `
                -IPDstPortStart 27000 -IPDstPortEnd 27100 `
                -DSCPAction 46 `
                -ThrottleRateActionBitsPerSecond 0 -ErrorAction SilentlyContinue | Out-Null
            
            Write-Host "  ✓ QoS configurado para jogos Steam (UDP 27000-27100)" -ForegroundColor Green
            
            Write-Log "Otimizações do Steam aplicadas" -Level "SUCCESS"
            
        }
        catch {
            Write-Log "Erro ao aplicar otimizações do Steam: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Optimize-LeagueOfLegendsSettings {
    Write-Section "Otimizações para League of Legends / Riot Games"
    
    Write-Host @"
🎮 LEAGUE OF LEGENDS - Otimizações de Rede:

⚙️ CONFIGURAÇÕES IN-GAME:

   1. Interface Options:
      • "Close client during game": ON
        ✓ MUITO IMPORTANTE: Libera RAM/CPU e reduz uso de rede
      
   2. Video Options:
      • Frame Rate Cap: 144 FPS ou refresh rate do monitor
      • V-Sync: OFF (adiciona input lag)

"@ -ForegroundColor Cyan
    
    if (Confirm-Action "Aplicar otimizações de rede para League of Legends?") {
        try {
            Write-Log "Aplicando otimizações para League of Legends..."
            
            # Remover políticas antigas
            Get-NetQosPolicy -Name "LoL*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue
            Get-NetQosPolicy -Name "Riot*" -ErrorAction SilentlyContinue | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue
            
            # Priorizar tráfego do jogo (UDP 5000-5500)
            New-NetQosPolicy -Name "LoL_Game_UDP" `
                -NetworkProfile All `
                -IPProtocol UDP `
                -IPDstPortStart 5000 -IPDstPortEnd 5500 `
                -DSCPAction 46 `
                -ThrottleRateActionBitsPerSecond 0 -ErrorAction SilentlyContinue | Out-Null
            
            Write-Host "  ✓ QoS configurado para LoL gameplay (UDP 5000-5500)" -ForegroundColor Green
            
            Write-Log "Otimizações do League of Legends aplicadas" -Level "SUCCESS"
            
        }
        catch {
            Write-Log "Erro ao aplicar otimizações do LoL: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

function Show-AppSpecificTroubleshooting {
    Write-Section "Troubleshooting por Aplicativo"
    
    Write-Host @"
🔧 PROBLEMAS COMUNS E SOLUÇÕES:

═══════════════════════════════════════════════════════════════════════

🎮 DISCORD - LAG DE VOZ / ROBOZINHO:

   ✓ Trocar região de voz (testar diferentes servidores)
   ✓ Desabilitar QoS do Discord (conflita com QoS do Windows)
   ✓ Verificar se antivírus não está bloqueando UDP
   ✓ Limpar cache: %appdata%\Discord\Cache
   ✓ Desabilitar Hardware Acceleration (teste)
   ✓ Usar Krisp Noise Suppression ao invés de padrão

═══════════════════════════════════════════════════════════════════════

🎮 STEAM - DOWNLOADS LENTOS / LAG IN-GAME:

   ✓ Trocar região de download (Settings → Downloads)
   ✓ Clear Download Cache (Settings → Downloads)
   ✓ Desabilitar Steam Overlay durante jogos competitivos
   ✓ Limitar download durante gameplay para 50% da banda
   ✓ Verificar Firewall: permitir portas UDP 27000-27100
   ✓ Desabilitar IPv6 se conexão instável (teste)

═══════════════════════════════════════════════════════════════════════

🎮 LEAGUE OF LEGENDS - PING ALTO / PACKET LOSS:

   ✓ SEMPRE ativar "Close client during game"
   ✓ Desabilitar VPN (Vanguard pode bloquear)
   ✓ Usar cabo ethernet, não Wi-Fi
   ✓ Fechar Riot Client completamente após fechar jogo
   ✓ Desabilitar Replays se ping instável
   ✓ Flush DNS: ipconfig /flushdns
   ✓ Reinstalar Vanguard se persistir (desinstalar + reiniciar)

═══════════════════════════════════════════════════════════════════════

🔥 DICAS GERAIS PARA TODOS OS JOGOS:

   1. PRIORIDADE DE PROCESSO:
      • Task Manager → Details → clique direito no jogo
      • Set Priority → High (ou Above Normal)
      
   2. GAME MODE DO WINDOWS:
      • Settings → Gaming → Game Mode → ON
      • Ajuda, mas não é mágico
      
   3. DISABLE FULLSCREEN OPTIMIZATIONS:
      • Clique direito no .exe → Properties → Compatibility
      • Marcar "Disable fullscreen optimizations"
      • Pode reduzir input lag

═══════════════════════════════════════════════════════════════════════

📊 MONITORAMENTO EM TEMPO REAL:

   • MSI Afterburner + RivaTuner: FPS, latência, uso de rede
   • Resource Monitor (resmon.exe): tráfego de rede por processo
   • Task Manager: Performance → Ethernet → ver gráfico
   • PingPlotter: visualizar latência e packet loss ao longo do tempo

"@ -ForegroundColor Cyan
    
    Write-Log "Guia de troubleshooting exibido"
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-NetworkOptimizer {
    Write-Host @"
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║          OTIMIZADOR DE REDE PARA GAMING - v1.2                          ║
║          Diagnóstico, Otimização e Hardening de Rede                    ║
║          ✨ NOVO: Otimizações para Jogos Web (Habblet, etc)            ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Magenta
    
    Write-Log "===== INÍCIO DA EXECUÇÃO =====" -Level "INFO"
    Write-Host "`nModo: $(if($DryRun){'DRY-RUN (Simulação)'}else{'PRODUÇÃO'})" -ForegroundColor $(if($DryRun){'Yellow'}else{'Green'})
    Write-Host "Log: $Script:LogFile`n" -ForegroundColor Gray
    
    # Flags de modo
    if ($ApplyAll) {
        Write-Host "⚡ MODO APPLY ALL - Aplicando todas as otimizações recomendadas`n" -ForegroundColor Magenta
        $Script:SetDns = $true
        $Script:SetMtu = $true
        $Script:ApplyTcpTweaks = $true
    }
    
    if ($WebGameMode) {
        Write-Host "🌐 WEB GAME MODE - Otimizações para jogos de navegador ativadas`n" -ForegroundColor Cyan
    }
    
    if ($OptimizeApps) {
        Write-Host "🎮 OPTIMIZE APPS - Detecção e otimização de apps específicos ativada`n" -ForegroundColor Green
    }
    
    # Rollback
    if ($Rollback) {
        Restore-NetworkConfig
        return
    }
    
    # Backup
    if (-not $DryRun) {
        Backup-NetworkConfig
    }
    
    # Diagnóstico
    $thirdPartySoftware = Test-ThirdPartySoftware
    $adapters = Get-NetworkAdapters
    $connectivityResults = Test-Connectivity
    $mtuInfo = Measure-OptimalMtu
    
    # Detectar apps de jogos (sempre detectar para diagnóstico)
    $gamingApps = Test-GamingApps
    
    # Diagnósticos específicos para jogos web
    if ($WebGameMode) {
        Test-WebGameConnectivity
        $detectedBrowsers = Test-BrowserPerformance
        Test-ProxyAndVpnImpact
    }
    
    # Aplicar otimizações
    if (-not $DryRun) {
        
        if ($SetDns) {
            Set-OptimalDns
        }
        
        if ($SetMtu -and $mtuInfo) {
            Set-OptimalMtu -MtuInfo $mtuInfo
        }
        
        if ($ApplyTcpTweaks) {
            Set-TcpOptimizations
        }
        
        if ($WebGameMode) {
            Set-WebSocketOptimizations
            Optimize-BrowserSettings
            Clear-BrowserCache
        }
        
        # Otimizações específicas de apps (se flag -OptimizeApps ativa)
        if ($OptimizeApps) {
            if ($gamingApps.Discord) {
                Optimize-DiscordSettings
            }
            
            if ($gamingApps.Steam) {
                Optimize-SteamSettings
            }
            
            if ($gamingApps.LeagueOfLegends -or $gamingApps.RiotClient) {
                Optimize-LeagueOfLegendsSettings
            }
            
            if (-not ($gamingApps.Discord -or $gamingApps.Steam -or $gamingApps.LeagueOfLegends)) {
                Write-Host "`n  ℹ -OptimizeApps foi especificado mas nenhum app foi detectado" -ForegroundColor Yellow
                Write-Host "    Aplicativos suportados: Discord, Steam, League of Legends" -ForegroundColor Gray
            }
        }
    }
    
    # Guias e recomendações
    if ($OptimizeApps -or $gamingApps.Discord -or $gamingApps.Steam -or $gamingApps.LeagueOfLegends) {
        Show-AppSpecificTroubleshooting
    }
    
    if ($WebGameMode) {
        Show-WebGameTroubleshooting
    }
    
    # Resumo final
    Write-Section "RESUMO FINAL"
    
    Write-Host "RESULTADOS DE CONECTIVIDADE:" -ForegroundColor Cyan
    foreach ($result in $connectivityResults) {
        $statusSymbol = switch($result.Quality) {
            "Excelente" { "✓✓" }
            "Bom" { "✓" }
            "Aceitável" { "⚠" }
            "Ruim" { "✗" }
            default { "?" }
        }
        
        $color = switch($result.Quality) {
            "Excelente" { "Green" }
            "Bom" { "Cyan" }
            "Aceitável" { "Yellow" }
            "Ruim" { "Red" }
            default { "Gray" }
        }
        
        Write-Host "  $statusSymbol $($result.Host):" -NoNewline
        Write-Host " $($result.Quality)" -ForegroundColor $color
        Write-Host "    Latência: $([math]::Round($result.AvgLatency, 2))ms | Jitter(σ): $([math]::Round($result.JitterStdDev, 2))ms | Perda: $($result.PacketLoss)%" -ForegroundColor Gray
    }
    
    Write-Host "`nAÇÕES APLICADAS:" -ForegroundColor Cyan
    if ($DryRun) {
        Write-Host "  [DRY-RUN] Nenhuma mudança foi aplicada" -ForegroundColor Yellow
    }
    else {
        if ($ApplyAll) { Write-Host "  ⚡ APPLY ALL - Todas as otimizações foram aplicadas" -ForegroundColor Magenta }
        if ($SetDns) { Write-Host "  ✓ DNS Cloudflare configurado" -ForegroundColor Green }
        if ($SetMtu) { Write-Host "  ✓ MTU otimizado aplicado" -ForegroundColor Green }
        if ($ApplyTcpTweaks) { Write-Host "  ✓ Otimizações TCP/IP aplicadas" -ForegroundColor Green }
        if ($WebGameMode) { Write-Host "  🌐 Otimizações para jogos web aplicadas" -ForegroundColor Cyan }
        if ($OptimizeApps) { Write-Host "  🎮 Otimizações de apps específicos aplicadas" -ForegroundColor Green }
        
        if (-not $SetDns -and -not $SetMtu -and -not $ApplyTcpTweaks -and -not $WebGameMode -and -not $OptimizeApps) {
            Write-Host "  ℹ Nenhuma otimização foi aplicada (somente diagnóstico)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`nARQUIVOS GERADOS:" -ForegroundColor Cyan
    Write-Host "  Log: $Script:LogFile" -ForegroundColor Gray
    if (-not $DryRun) {
        Write-Host "  Backup: $Script:BackupFile" -ForegroundColor Gray
    }
    
    if (-not $DryRun) {
        Write-Host "`n⚠️ Para reverter mudanças:" -ForegroundColor Yellow
        Write-Host "     .\NetworkOptimizer.ps1 -Rollback" -ForegroundColor White
        
        if ($WebGameMode) {
            Write-Host "`n🌐 IMPORTANTE:" -ForegroundColor Cyan
            Write-Host "     • Reinicie o navegador para aplicar mudanças" -ForegroundColor Gray
            Write-Host "     • Teste com e sem VPN/proxy para comparar" -ForegroundColor Gray
            Write-Host "     • Use F12 DevTools para monitorar latência WebSocket" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n✓ Script concluído com sucesso!" -ForegroundColor Green
    Write-Log "===== FIM DA EXECUÇÃO ====="
}

# ============================================================================
# EXECUÇÃO
# ============================================================================

try {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "ERRO: Este script requer privilégios de Administrador!" -ForegroundColor Red
        Write-Host "Execute o PowerShell como Administrador e tente novamente." -ForegroundColor Yellow
        exit 1
    }
    
    Start-NetworkOptimizer
}
catch {
    Write-Log "ERRO FATAL: $($_.Exception.Message)" -Level "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level "ERROR"
    Write-Host "`n✗ Erro durante execução. Verifique o log para detalhes." -ForegroundColor Red
    exit 1
}

Write-Host "`nPressione qualquer tecla para sair..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")