#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Смена / восстановление MAC-адреса сетевого адаптера (для обхода FishPoker IMEI-блокировки).

.DESCRIPTION
    FishPoker использует MAC-адрес основного сетевого адаптера как IMEI/openUid.
    Скрипт позволяет:
      - Показать текущий MAC и адаптеры                   (--show)
      - Установить случайный MAC                          (--random)
      - Установить конкретный MAC                         (--set XX-XX-XX-XX-XX-XX)
      - Восстановить оригинальный (аппаратный) MAC        (--restore)

    ВАЖНО: Требует запуска от имени администратора.
    После смены MAC адаптер перезапускается (~2-3 сек без сети).

.EXAMPLE
    .\mac_spoof.ps1 -show
    .\mac_spoof.ps1 -random
    .\mac_spoof.ps1 -set AA-BB-CC-DD-EE-FF
    .\mac_spoof.ps1 -restore
    .\mac_spoof.ps1 -random -adapter "Ethernet 2"
#>

param(
    [switch]$show,
    [switch]$random,
    [switch]$restore,
    [string]$set = "",
    [string]$adapter = ""
)

# ========== Helpers ==========

function Get-PhysicalAdapters {
    # Возвращает физические Ethernet/Wi-Fi адаптеры (не виртуальные)
    Get-NetAdapter | Where-Object {
        $_.Status -eq "Up" -and
        $_.InterfaceDescription -notmatch "Virtual|Hyper-V|VPN|TAP|Bluetooth|Loopback|Radmin"
    }
}

function Find-RegistryPath {
    param([string]$adapterDesc)
    # Ищем ключ реестра для конкретного адаптера по описанию
    $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    $subkeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
    foreach ($key in $subkeys) {
        $desc = (Get-ItemProperty -Path $key.PSPath -Name "DriverDesc" -ErrorAction SilentlyContinue).DriverDesc
        if ($desc -and $desc -eq $adapterDesc) {
            return $key.PSPath
        }
    }
    return $null
}

function Generate-RandomMAC {
    # Генерирует случайный MAC: первый байт чётный (unicast) и не multicast
    $bytes = @()
    for ($i = 0; $i -lt 6; $i++) {
        $bytes += Get-Random -Minimum 0 -Maximum 256
    }
    # Убеждаемся что бит multicast сброшен, бит locally-administered установлен
    $bytes[0] = ($bytes[0] -band 0xFE) -bor 0x02
    return ($bytes | ForEach-Object { "{0:X2}" -f $_ }) -join "-"
}

function Validate-MAC {
    param([string]$mac)
    return $mac -match "^[0-9A-Fa-f]{2}(-[0-9A-Fa-f]{2}){5}$"
}

function Restart-Adapter {
    param([string]$name)
    Write-Host "[*] Перезапуск адаптера '$name' ..." -ForegroundColor Yellow
    Disable-NetAdapter -Name $name -Confirm:$false -ErrorAction Stop
    Start-Sleep -Seconds 2
    Enable-NetAdapter -Name $name -Confirm:$false -ErrorAction Stop
    Start-Sleep -Seconds 3
    Write-Host "[OK] Адаптер '$name' перезапущен" -ForegroundColor Green
}

# ========== Main ==========

# Проверка прав администратора
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin -and -not $show) {
    Write-Host "[ERROR] Требуются права администратора!" -ForegroundColor Red
    Write-Host "        Запустите PowerShell от имени администратора." -ForegroundColor Red
    exit 1
}

# Выбор адаптера
$adapters = Get-PhysicalAdapters
if (-not $adapters) {
    Write-Host "[ERROR] Не найдено активных физических сетевых адаптеров" -ForegroundColor Red
    exit 1
}

# --show
if ($show) {
    Write-Host "`n=== Активные физические адаптеры ===" -ForegroundColor Cyan
    foreach ($a in $adapters) {
        $regPath = Find-RegistryPath -adapterDesc $a.InterfaceDescription
        $spoofed = ""
        if ($regPath) {
            $na = (Get-ItemProperty -Path $regPath -Name "NetworkAddress" -ErrorAction SilentlyContinue).NetworkAddress
            if ($na) {
                $formatted = ($na -replace '(.{2})', '$1-').TrimEnd('-')
                $spoofed = "  [spoofed -> $formatted]"
            }
        }
        Write-Host ("  {0,-25} MAC: {1}{2}" -f $a.Name, $a.MacAddress, $spoofed)
        Write-Host ("  {0,-25} Desc: {1}" -f "", $a.InterfaceDescription) -ForegroundColor Gray
    }
    Write-Host ""
    exit 0
}

# Определяем целевой адаптер
$target = $null
if ($adapter) {
    $target = $adapters | Where-Object { $_.Name -eq $adapter }
    if (-not $target) {
        Write-Host "[ERROR] Адаптер '$adapter' не найден среди активных" -ForegroundColor Red
        Write-Host "        Доступные:" -ForegroundColor Yellow
        $adapters | ForEach-Object { Write-Host "          $($_.Name)" }
        exit 1
    }
} else {
    if (($adapters | Measure-Object).Count -gt 1) {
        Write-Host "[WARN] Несколько активных адаптеров. Используется первый:" -ForegroundColor Yellow
        $adapters | ForEach-Object { Write-Host "         $($_.Name) - $($_.MacAddress)" }
    }
    $target = $adapters | Select-Object -First 1
}

Write-Host "[INFO] Адаптер: $($target.Name) ($($target.InterfaceDescription))" -ForegroundColor Cyan
Write-Host "[INFO] Текущий MAC: $($target.MacAddress)" -ForegroundColor Cyan

$regPath = Find-RegistryPath -adapterDesc $target.InterfaceDescription
if (-not $regPath) {
    Write-Host "[ERROR] Не найден ключ реестра для адаптера" -ForegroundColor Red
    exit 1
}

# --restore
if ($restore) {
    $existing = (Get-ItemProperty -Path $regPath -Name "NetworkAddress" -ErrorAction SilentlyContinue).NetworkAddress
    if (-not $existing) {
        Write-Host "[INFO] NetworkAddress не задан — MAC уже оригинальный" -ForegroundColor Green
        exit 0
    }
    Write-Host "[*] Удаление NetworkAddress из реестра (возврат к аппаратному MAC) ..." -ForegroundColor Yellow
    Remove-ItemProperty -Path $regPath -Name "NetworkAddress" -ErrorAction Stop
    Restart-Adapter -name $target.Name

    $newAdapter = Get-NetAdapter -Name $target.Name
    Write-Host "[OK] MAC восстановлен: $($newAdapter.MacAddress)" -ForegroundColor Green
    exit 0
}

# --random or --set
$newMAC = ""
if ($random) {
    $newMAC = Generate-RandomMAC
    Write-Host "[INFO] Сгенерирован случайный MAC: $newMAC" -ForegroundColor Yellow
} elseif ($set) {
    $newMAC = $set.ToUpper().Trim()
    if (-not (Validate-MAC -mac $newMAC)) {
        Write-Host "[ERROR] Некорректный формат MAC: $set" -ForegroundColor Red
        Write-Host "        Ожидается: XX-XX-XX-XX-XX-XX" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Использование:" -ForegroundColor Yellow
    Write-Host "  .\mac_spoof.ps1 -show                        Показать адаптеры и MAC"
    Write-Host "  .\mac_spoof.ps1 -random                      Случайный MAC"
    Write-Host "  .\mac_spoof.ps1 -set AA-BB-CC-DD-EE-FF       Конкретный MAC"
    Write-Host "  .\mac_spoof.ps1 -restore                     Восстановить оригинальный"
    Write-Host "  ... -adapter `"Ethernet 2`"                    Выбрать адаптер"
    exit 0
}

# Сохраняем оригинальный MAC перед первой заменой (для информации)
$origNA = (Get-ItemProperty -Path $regPath -Name "NetworkAddress" -ErrorAction SilentlyContinue).NetworkAddress
if ($origNA) {
    $origFormatted = ($origNA -replace '(.{2})', '$1-').TrimEnd('-')
    Write-Host "[INFO] Предыдущий spoofed MAC: $origFormatted" -ForegroundColor Gray
}

# Записываем новый MAC без дефисов
$macClean = $newMAC -replace "-", ""
Write-Host "[*] Запись NetworkAddress = $macClean в реестр ..." -ForegroundColor Yellow
Set-ItemProperty -Path $regPath -Name "NetworkAddress" -Value $macClean -Type String -ErrorAction Stop

# Перезапуск адаптера
Restart-Adapter -name $target.Name

# Проверка
$newAdapter = Get-NetAdapter -Name $target.Name
Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  MAC изменён!" -ForegroundColor Green
Write-Host "  Новый MAC:  $($newAdapter.MacAddress)" -ForegroundColor Green
Write-Host "  FishPoker IMEI теперь: $($newAdapter.MacAddress)" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Для восстановления: .\mac_spoof.ps1 -restore" -ForegroundColor Yellow
