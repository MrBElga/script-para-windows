Write-Host "=== ATIVANDO MODO DESEMPENHO MAXIMO ===" -ForegroundColor Green

# Ativar plano de energia Desempenho Máximo
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
powercfg -setactive e9a42b02-d5df-448d-aa00-03f14749eb61

# Impedir que o Windows desligue a placa de rede
Get-NetAdapter | ForEach-Object {
    powercfg -deviceenablewake "$($_.Name)"
}

# Reset completo da pilha de rede
netsh int ip reset
netsh winsock reset

# Limpeza e reconfiguração de DNS
ipconfig /flushdns
ipconfig /release
ipconfig /renew

# Definir DNS confiáveis
$interfaces = Get-DnsClient | Where-Object {$_.InterfaceAlias -notlike "*Loopback*"}
foreach ($i in $interfaces) {
    Set-DnsClientServerAddress -InterfaceIndex $i.InterfaceIndex -ServerAddresses ("1.1.1.1","8.8.8.8")
}

# Desativar IPv6 adaptativamente (opcional mas recomendado em casos instáveis)
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xff -PropertyType DWord -Force

# Aumentar limite de portas TCP/UDP
netsh int ipv4 set dynamicport udp start=10000 num=55000
netsh int ipv4 set dynamicport tcp start=10000 num=55000

# Limpar cache ARP
arp -d *

Write-Host "=== CONFIGURAÇÃO CONCLUÍDA ===" -ForegroundColor Cyan
Write-Host "REINICIE O COMPUTADOR PARA APLICAR TUDO" -ForegroundColor Yellow
