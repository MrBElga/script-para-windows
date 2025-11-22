#requires -RunAsAdministrator
<#
.SYNOPSIS
    Diagnóstico e Otimização de Rede - Solução para Conexões Instáveis
.DESCRIPTION
    Corrige problemas de desconexão, timeouts DNS, esgotamento de portas
    e conflitos de adaptadores virtuais
#>

[CmdletBinding()]
param(
    [switch]$DiagnosticoCompleto,
    [switch]$AplicarOtimizacoes,
    [switch]$CorrigirAgora
)

$ErrorActionPreference = "Continue"

# ============================================================================
# FUNÇÕES DE DIAGNÓSTICO
# ============================================================================

function Write-Colored {
    param($Text, $Color = "White")
    Write-Host $Text -ForegroundColor $Color
}

function Test-NetworkHealth {
    Write-Colored "`n=== DIAGNÓSTICO DE SAÚDE DA REDE ===" "Cyan"
    
    # 1. Testar DNS
    Write-Colored "`n[1] Testando resolução DNS..." "Yellow"
    $dnsTests = @("google.com", "cloudflare.com", "1.1.1.1")
    $dnsOk = 0
    
    foreach ($host in $dnsTests) {
        try {
            $result = Resolve-DnsName $host -ErrorAction Stop
            Write-Colored "  ✓ $host - OK" "Green"
            $dnsOk++
        }
        catch {
            Write-Colored "  ✗ $host - FALHOU" "Red"
        }
    }
    
    if ($dnsOk -eq 0) {
        Write-Colored "  ⚠ PROBLEMA CRÍTICO: DNS não está funcionando!" "Red"
        return $false
    }
    
    # 2. Verificar portas UDP disponíveis
    Write-Colored "`n[2] Verificando disponibilidade de portas UDP..." "Yellow"
    
    $udpStats = netsh int ipv4 show dynamicport udp
    Write-Colored "  Status atual de portas UDP:" "Gray"
    $udpStats | ForEach-Object { Write-Host "    $_" }
    
    # 3. Identificar adaptadores problemáticos
    Write-Colored "`n[3] Analisando adaptadores de rede..." "Yellow"
    
    $allAdapters = Get-NetAdapter
    $problematicAdapters = @()
    
    foreach ($adapter in $allAdapters) {
        $isVirtual = $adapter.Name -match "vEthernet|Tailscale|Loopback|Virtual|Hyper-V"
        
        if ($adapter.Status -eq "Up") {
            $color = if ($isVirtual) { "Yellow" } else { "Green" }
            $type = if ($isVirtual) { "[VIRTUAL]" } else { "[FÍSICO]" }
            Write-Colored "  $type $($adapter.Name) - $($adapter.Status)" $color
            
            if ($isVirtual) {
                $problematicAdapters += $adapter.Name
            }
        }
    }
    
    if ($problematicAdapters.Count -gt 0) {
        Write-Colored "`n  ⚠ Adaptadores virtuais detectados podem causar conflitos:" "Yellow"
        $problematicAdapters | ForEach-Object { Write-Host "    - $_" }
    }
    
    # 4. Testar conectividade real
    Write-Colored "`n[4] Testando conectividade (20 pings)..." "Yellow"
    
    $pingResults = Test-Connection -ComputerName 1.1.1.1 -Count 20 -ErrorAction SilentlyContinue
    
    if ($pingResults) {
        $successful = ($pingResults | Measure-Object).Count
        $avgLatency = ($pingResults | Measure-Object -Property Latency -Average).Average
        $packetLoss = ((20 - $successful) / 20) * 100
        
        Write-Colored "  Pacotes enviados: 20" "Gray"
        Write-Colored "  Pacotes recebidos: $successful" $(if($successful -ge 18){"Green"}else{"Red"})
        Write-Colored "  Perda de pacotes: $packetLoss%" $(if($packetLoss -le 5){"Green"}else{"Red"})
        Write-Colored "  Latência média: $([math]::Round($avgLatency, 2))ms" $(if($avgLatency -le 50){"Green"}else{"Yellow"})
        
        return ($packetLoss -le 10 -and $successful -ge 15)
    }
    else {
        Write-Colored "  ✗ FALHA TOTAL DE CONECTIVIDADE" "Red"
        return $false
    }
}

function Get-NetworkIssues {
    Write-Colored "`n=== IDENTIFICANDO PROBLEMAS ESPECÍFICOS ===" "Cyan"
    
    $issues = @()
    
    # Verificar Event Viewer para erros recentes de rede
    Write-Colored "`nVerificando logs do sistema (últimas 2 horas)..." "Yellow"
    
    try {
        $networkErrors = Get-WinEvent -FilterHashtable @{
            LogName = 'System'
            Level = 2,3
            StartTime = (Get-Date).AddHours(-2)
        } -MaxEvents 50 -ErrorAction SilentlyContinue | 
        Where-Object { $_.Message -match "DNS|network|TCP|UDP|porta|port" }
        
        if ($networkErrors) {
            Write-Colored "  Erros de rede encontrados:" "Red"
            $networkErrors | Select-Object -First 5 | ForEach-Object {
                Write-Host "    - $($_.TimeCreated): $($_.Message.Substring(0, [Math]::Min(80, $_.Message.Length)))..."
            }
            $issues += "Erros recentes no Event Viewer"
        }
    }
    catch {
        Write-Colored "  Não foi possível acessar Event Viewer" "Gray"
    }
    
    # Verificar serviços críticos
    Write-Colored "`nVerificando serviços de rede..." "Yellow"
    
    $criticalServices = @("Dnscache", "Dhcp", "WinHttpAutoProxySvc")
    foreach ($svc in $criticalServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne "Running") {
                Write-Colored "  ✗ $($service.DisplayName) não está rodando!" "Red"
                $issues += "Serviço $($service.DisplayName) parado"
            }
            else {
                Write-Colored "  ✓ $($service.DisplayName) - OK" "Green"
            }
        }
    }
    
    return $issues
}

# ============================================================================
# FUNÇÕES DE CORREÇÃO
# ============================================================================

function Repair-DnsConfiguration {
    Write-Colored "`n=== CORRIGINDO CONFIGURAÇÃO DNS ===" "Cyan"
    
    # Limpar cache DNS
    Write-Colored "Limpando cache DNS..." "Yellow"
    ipconfig /flushdns | Out-Null
    Write-Colored "  ✓ Cache DNS limpo" "Green"
    
    # Configurar DNS Cloudflare apenas em adaptadores físicos
    $physicalAdapters = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and
        $_.Name -notmatch "vEthernet|Tailscale|Loopback|Virtual|Hyper-V"
    }
    
    foreach ($adapter in $physicalAdapters) {
        Write-Colored "Configurando DNS para: $($adapter.Name)" "Yellow"
        try {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses @("1.1.1.1", "1.0.0.1") -ErrorAction Stop
            Write-Colored "  ✓ DNS Cloudflare configurado" "Green"
        }
        catch {
            Write-Colored "  ✗ Erro ao configurar DNS: $($_.Exception.Message)" "Red"
        }
    }
    
    # Reiniciar serviço DNS
    Write-Colored "Reiniciando serviço DNS..." "Yellow"
    Restart-Service Dnscache -Force
    Write-Colored "  ✓ Serviço DNS reiniciado" "Green"
}

function Repair-PortExhaustion {
    Write-Colored "`n=== CORRIGINDO ESGOTAMENTO DE PORTAS ===" "Cyan"
    
    Write-Colored "Expandindo pool de portas dinâmicas..." "Yellow"
    
    # TCP
    netsh int ipv4 set dynamicport tcp start=10000 num=55535 | Out-Null
    Write-Colored "  ✓ Portas TCP: 10000-65535 (55535 portas)" "Green"
    
    # UDP
    netsh int ipv4 set dynamicport udp start=10000 num=55535 | Out-Null
    Write-Colored "  ✓ Portas UDP: 10000-65535 (55535 portas)" "Green"
    
    # Limpar conexões TIME_WAIT antigas
    Write-Colored "Otimizando TcpTimedWaitDelay..." "Yellow"
    
    $tcpParams = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    
    # Reduzir tempo de TIME_WAIT de 240s para 30s
    Set-ItemProperty -Path $tcpParams -Name "TcpTimedWaitDelay" -Value 30 -Type DWord -Force
    Write-Colored "  ✓ TIME_WAIT reduzido para 30 segundos" "Green"
    
    # Permitir mais conexões TIME_WAIT
    Set-ItemProperty -Path $tcpParams -Name "MaxUserPort" -Value 65534 -Type DWord -Force
    Write-Colored "  ✓ MaxUserPort configurado" "Green"
}

function Repair-NetworkStack {
    Write-Colored "`n=== REPARANDO PILHA DE REDE ===" "Cyan"
    
    Write-Colored "Resetando Winsock e TCP/IP..." "Yellow"
    
    # Reset Winsock
    netsh winsock reset | Out-Null
    Write-Colored "  ✓ Winsock resetado" "Green"
    
    # Reset TCP/IP
    netsh int ip reset | Out-Null
    Write-Colored "  ✓ TCP/IP resetado" "Green"
    
    # Limpar cache ARP
    arp -d * 2>$null
    Write-Colored "  ✓ Cache ARP limpo" "Green"
}

function Optimize-NetworkAdapter {
    Write-Colored "`n=== OTIMIZANDO ADAPTADORES FÍSICOS ===" "Cyan"
    
    $physicalAdapters = Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and
        $_.Name -notmatch "vEthernet|Tailscale|Loopback|Virtual|Hyper-V"
    }
    
    foreach ($adapter in $physicalAdapters) {
        Write-Colored "`nConfigurando: $($adapter.Name)" "Yellow"
        
        # Desabilitar economia de energia (método correto)
        try {
            $powerMgmt = Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | 
                Where-Object { $_.InstanceName -match [regex]::Escape($adapter.PnPDeviceID) }
            
            if ($powerMgmt) {
                $powerMgmt.Enable = $false
                $powerMgmt.Put() | Out-Null
                Write-Colored "  ✓ Economia de energia desabilitada" "Green"
            }
        }
        catch {
            Write-Colored "  ⚠ Não foi possível alterar economia de energia" "Yellow"
        }
        
        # Otimizações avançadas de adaptador
        try {
            # Desabilitar offloads que podem causar problemas
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "InterruptModeration" -RegistryValue 0 -ErrorAction SilentlyContinue
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "FlowControl" -RegistryValue 0 -ErrorAction SilentlyContinue
            Write-Colored "  ✓ Propriedades avançadas otimizadas" "Green"
        }
        catch {
            Write-Colored "  ⚠ Algumas propriedades não puderam ser alteradas" "Yellow"
        }
    }
}

function Optimize-TcpSettings {
    Write-Colored "`n=== OTIMIZANDO TCP/IP GLOBAL ===" "Cyan"
    
    # AutoTuning Normal (melhor para maioria dos casos)
    netsh int tcp set global autotuninglevel=normal | Out-Null
    Write-Colored "  ✓ AutoTuning: Normal" "Green"
    
    # Habilitar Timestamps
    netsh int tcp set global timestamps=enabled | Out-Null
    Write-Colored "  ✓ Timestamps: Enabled" "Green"
    
    # Initial RTO otimizado
    netsh int tcp set global initialRto=2000 | Out-Null
    Write-Colored "  ✓ Initial RTO: 2000ms" "Green"
    
    # RSS habilitado (melhor performance multi-core)
    netsh int tcp set global rss=enabled | Out-Null
    Write-Colored "  ✓ RSS: Enabled" "Green"
    
    # Chimney Offload desabilitado (pode causar problemas)
    netsh int tcp set global chimney=disabled | Out-Null
    Write-Colored "  ✓ Chimney: Disabled" "Green"
}

function Disable-IPv6IfProblematic {
    Write-Colored "`n=== VERIFICANDO IPv6 ===" "Cyan"
    
    # IPv6 pode causar problemas de timeout DNS
    $response = Read-Host "Desabilitar IPv6? (pode melhorar estabilidade) [S/N]"
    
    if ($response -eq "S" -or $response -eq "s") {
        Write-Colored "Desabilitando IPv6..." "Yellow"
        
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" `
            -Name "DisabledComponents" -Value 0xff -PropertyType DWord -Force | Out-Null
        
        Write-Colored "  ✓ IPv6 desabilitado (requer reinicialização)" "Green"
    }
    else {
        Write-Colored "  IPv6 mantido habilitado" "Gray"
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-NetworkRepair {
    Write-Colored @"
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║     DIAGNÓSTICO E CORREÇÃO DE REDE - v2.0                          ║
║     Solução para conexões instáveis e timeouts                      ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"@ "Magenta"

    # Verificar se é admin
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Colored "`n✗ ERRO: Execute como Administrador!" "Red"
        exit 1
    }
    
    # Fase 1: Diagnóstico
    Write-Colored "`n═══ FASE 1: DIAGNÓSTICO ═══" "Magenta"
    
    $healthOk = Test-NetworkHealth
    $issues = Get-NetworkIssues
    
    if ($issues.Count -gt 0) {
        Write-Colored "`n⚠ PROBLEMAS IDENTIFICADOS:" "Red"
        $issues | ForEach-Object { Write-Host "  - $_" }
    }
    
    # Decisão de aplicar correções
    if ($CorrigirAgora) {
        $applyFix = $true
    }
    elseif (-not $healthOk -or $issues.Count -gt 0) {
        Write-Colored "`n═══ FASE 2: CORREÇÃO ═══" "Magenta"
        $response = Read-Host "`nProblemas detectados. Aplicar correções? [S/N]"
        $applyFix = ($response -eq "S" -or $response -eq "s")
    }
    else {
        Write-Colored "`n✓ Rede aparenta estar saudável!" "Green"
        $response = Read-Host "`nAplicar otimizações preventivas? [S/N]"
        $applyFix = ($response -eq "S" -or $response -eq "s")
    }
    
    if ($applyFix) {
        Write-Colored "`n═══ APLICANDO CORREÇÕES ═══" "Magenta"
        
        Repair-DnsConfiguration
        Repair-PortExhaustion
        Repair-NetworkStack
        Optimize-NetworkAdapter
        Optimize-TcpSettings
        Disable-IPv6IfProblematic
        
        Write-Colored "`n═══ CORREÇÕES APLICADAS ═══" "Green"
        Write-Colored "`n⚠ IMPORTANTE: Reinicie o computador para aplicar todas as mudanças!" "Yellow"
        
        $reboot = Read-Host "`nReiniciar agora? [S/N]"
        if ($reboot -eq "S" -or $reboot -eq "s") {
            Write-Colored "`nReiniciando em 10 segundos..." "Yellow"
            Start-Sleep -Seconds 10
            Restart-Computer -Force
        }
    }
    else {
        Write-Colored "`nNenhuma alteração foi feita." "Gray"
    }
    
    # Resumo final
    Write-Colored "`n═══ RESUMO ═══" "Cyan"
    Write-Colored "Diagnóstico: $(if($healthOk){'✓ OK'}else{'✗ Problemas detectados'})" $(if($healthOk){"Green"}else{"Red"})
    Write-Colored "Problemas encontrados: $($issues.Count)" $(if($issues.Count -eq 0){"Green"}else{"Yellow"})
    Write-Colored "Correções aplicadas: $(if($applyFix){'Sim'}else{'Não'})" $(if($applyFix){"Green"}else{"Gray"})
}

# Executar
Start-NetworkRepair