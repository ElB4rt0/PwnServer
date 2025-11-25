@echo off
REM ============================================================
REM Script: Verificar_RC4_Kerberos_Trusts.bat
REM Descripcion: Audita el uso de RC4 en Kerberos y Relaciones de Confianza
REM Ejecutar como Administrador en un Domain Controller
REM ============================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   AUDITORIA DE CIFRADO KERBEROS - RC4/DES EN TRUSTS
echo   Fecha: %date% %time%
echo ============================================================
echo.

REM Crear carpeta de salida
set "OUTPUT_DIR=C:\temp\Kerberos_Audit"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

set "REPORT=%OUTPUT_DIR%\Reporte_RC4_Trusts_%date:~-4%%date:~3,2%%date:~0,2%.txt"
set "LDIF_TRUSTS=%OUTPUT_DIR%\Trusts_EncryptionTypes.ldf"
set "POC_FILE=%OUTPUT_DIR%\POC_Detalle.txt"

REM Variables para determinar estado
set "VULNERABLE=0"
set "TRUST_RC4_FOUND=0"

echo Generando reporte en: %OUTPUT_DIR%
echo.

REM ============================================================
REM INICIO DEL REPORTE
REM ============================================================

echo ============================================================ > "%REPORT%"
echo   REPORTE DE AUDITORIA - RC4 EN RELACIONES DE CONFIANZA >> "%REPORT%"
echo   Fecha de ejecucion: %date% %time% >> "%REPORT%"
echo   Equipo: %COMPUTERNAME% >> "%REPORT%"
echo   Dominio: %USERDNSDOMAIN% >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo. >> "%REPORT%"

REM ============================================================
REM 1. OBTENER POC - DETALLE DE TRUSTS
REM ============================================================

echo [1/4] Obteniendo POC - Detalle de Trusts...

REM Crear archivo POC
echo ============================================================ > "%POC_FILE%"
echo   POC - PRUEBA DE CONCEPTO >> "%POC_FILE%"
echo   Uso de Algoritmos Obsoletos para Kerberos (RC4) en Trusts >> "%POC_FILE%"
echo   Fecha: %date% %time% >> "%POC_FILE%"
echo ============================================================ >> "%POC_FILE%"
echo. >> "%POC_FILE%"

REM ============================================================
REM 2. EJECUTAR VERIFICACION Y CAPTURAR POC
REM ============================================================

echo [2/4] Analizando configuracion de cifrado en Trusts...

REM Usar PowerShell para obtener detalle completo y POC
powershell -Command ^
"$vulnerable = $false; ^
$pocData = @(); ^
$resultScreen = ''; ^
try { ^
    Import-Module ActiveDirectory -ErrorAction Stop; ^
    $domain = Get-ADDomain; ^
    $trustObjects = Get-ADObject -SearchBase \"CN=System,$($domain.DistinguishedName)\" -Filter {ObjectClass -eq 'trustedDomain'} -Properties *; ^
    ^
    Write-Host ''; ^
    Write-Host '------------------------------------------------------------'; ^
    Write-Host '  POC - DETALLE DE RELACIONES DE CONFIANZA'; ^
    Write-Host '------------------------------------------------------------'; ^
    Write-Host ''; ^
    ^
    $tableData = @(); ^
    foreach ($t in $trustObjects) { ^
        $encType = $t.'msDS-SupportedEncryptionTypes'; ^
        $trustDir = switch($t.trustDirection) { 0{'Disabled'} 1{'Inbound'} 2{'Outbound'} 3{'Bidirectional'} default{'Unknown'} }; ^
        $trustTypeVal = switch($t.trustType) { 1{'Downlevel'} 2{'Uplevel'} 3{'MIT'} 4{'DCE'} default{'Unknown'} }; ^
        ^
        $algorithm = 'Default (RC4)'; ^
        $status = 'VULNERABLE'; ^
        $statusSymbol = '[X]'; ^
        ^
        if ($null -eq $encType -or $encType -eq 0) { ^
            $algorithm = 'Default (RC4)'; ^
            $status = 'VULNERABLE'; ^
            $statusSymbol = '[X]'; ^
            $vulnerable = $true; ^
        } elseif ($encType -eq 4) { ^
            $algorithm = 'RC4_HMAC'; ^
            $status = 'VULNERABLE'; ^
            $statusSymbol = '[X]'; ^
            $vulnerable = $true; ^
        } elseif ($encType -eq 24) { ^
            $algorithm = 'AES128 + AES256'; ^
            $status = 'SEGURO'; ^
            $statusSymbol = '[OK]'; ^
        } elseif ($encType -eq 16) { ^
            $algorithm = 'AES256'; ^
            $status = 'SEGURO'; ^
            $statusSymbol = '[OK]'; ^
        } elseif ($encType -eq 8) { ^
            $algorithm = 'AES128'; ^
            $status = 'SEGURO'; ^
            $statusSymbol = '[OK]'; ^
        } elseif ($encType -band 0x4) { ^
            $algorithm = \"RC4 + AES (Valor: $encType)\"; ^
            $status = 'PARCIAL'; ^
            $statusSymbol = '[!]'; ^
            $vulnerable = $true; ^
        } else { ^
            $algorithm = \"Valor: $encType\"; ^
            $status = 'VERIFICAR'; ^
            $statusSymbol = '[?]'; ^
        }; ^
        ^
        Write-Host \"  Trust Partner:    $($t.trustPartner)\"; ^
        Write-Host \"  Trust Type:       $trustTypeVal\"; ^
        Write-Host \"  Direction:        $trustDir\"; ^
        Write-Host \"  Encryption Value: $encType\"; ^
        Write-Host \"  Algorithm:        $algorithm\"; ^
        Write-Host \"  Estado:           $statusSymbol $status\"; ^
        Write-Host \"  DN:               $($t.DistinguishedName)\"; ^
        Write-Host ''; ^
        Write-Host '  --------------------------------------------------------'; ^
        Write-Host ''; ^
    }; ^
    ^
    Write-Host ''; ^
    Write-Host '============================================================'; ^
    Write-Host '  TABLA RESUMEN - POC'; ^
    Write-Host '============================================================'; ^
    Write-Host ''; ^
    Write-Host '  Trust Partner          | Direction     | Algorithm        | Estado'; ^
    Write-Host '  -----------------------|---------------|------------------|----------'; ^
    ^
    foreach ($t in $trustObjects) { ^
        $encType = $t.'msDS-SupportedEncryptionTypes'; ^
        $trustDir = switch($t.trustDirection) { 0{'Disabled'} 1{'Inbound'} 2{'Outbound'} 3{'Bidirectional'} default{'Unknown'} }; ^
        ^
        $algorithm = 'Default (RC4)'; ^
        $status = 'VULNERABLE'; ^
        ^
        if ($null -eq $encType -or $encType -eq 0) { ^
            $algorithm = 'Default (RC4)'; ^
            $status = 'VULNERABLE'; ^
        } elseif ($encType -eq 4) { ^
            $algorithm = 'RC4_HMAC'; ^
            $status = 'VULNERABLE'; ^
        } elseif ($encType -eq 24) { ^
            $algorithm = 'AES128+AES256'; ^
            $status = 'SEGURO'; ^
        } elseif ($encType -eq 16) { ^
            $algorithm = 'AES256'; ^
            $status = 'SEGURO'; ^
        } elseif ($encType -eq 8) { ^
            $algorithm = 'AES128'; ^
            $status = 'SEGURO'; ^
        } elseif ($encType -band 0x4) { ^
            $algorithm = 'RC4+AES'; ^
            $status = 'PARCIAL'; ^
        }; ^
        ^
        $partnerPad = $t.trustPartner.PadRight(22); ^
        $dirPad = $trustDir.PadRight(13); ^
        $algPad = $algorithm.PadRight(16); ^
        Write-Host \"  $partnerPad | $dirPad | $algPad | $status\"; ^
    }; ^
    ^
    Write-Host ''; ^
    Write-Host '============================================================'; ^
    Write-Host ''; ^
    ^
    if ($vulnerable) { ^
        exit 1; ^
    } else { ^
        exit 0; ^
    } ^
} catch { ^
    Write-Host \"Error: $($_.Exception.Message)\"; ^
    Write-Host 'Usando metodo alternativo...'; ^
    exit 2; ^
}" > "%POC_FILE%" 2>&1

set "PS_EXIT=%errorlevel%"

if %PS_EXIT% equ 1 (
    set "VULNERABLE=1"
    set "TRUST_RC4_FOUND=1"
)

REM Copiar POC al reporte principal
type "%POC_FILE%" >> "%REPORT%"

REM ============================================================
REM 3. METODO ALTERNATIVO SI FALLA POWERSHELL
REM ============================================================

if %PS_EXIT% equ 2 (
    echo [3/4] Ejecutando metodo alternativo...
    echo. >> "%REPORT%"
    echo ------------------------------------------------------------ >> "%REPORT%"
    echo   METODO ALTERNATIVO - DSQUERY >> "%REPORT%"
    echo ------------------------------------------------------------ >> "%REPORT%"
    echo. >> "%REPORT%"
    
    dsquery * "CN=System,DC=%USERDOMAIN%" -filter "(objectClass=trustedDomain)" -attr cn trustPartner msDS-SupportedEncryptionTypes trustDirection trustType 2>nul >> "%REPORT%"
    
    echo. >> "%REPORT%"
    echo   NOTA: Verificar manualmente los valores de msDS-SupportedEncryptionTypes >> "%REPORT%"
    echo   - NULL o 0 = Default (RC4) = VULNERABLE >> "%REPORT%"
    echo   - 4 = RC4 = VULNERABLE >> "%REPORT%"
    echo   - 24 = AES = SEGURO >> "%REPORT%"
    echo. >> "%REPORT%"
) else (
    echo [3/4] Verificacion con PowerShell completada...
)

REM ============================================================
REM 4. GENERAR RESULTADO FINAL CON POC
REM ============================================================

echo [4/4] Generando resultado final...

echo. >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo   REFERENCIA DE VALORES msDS-SupportedEncryptionTypes >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo. >> "%REPORT%"
echo   VALOR    ALGORITMO                      ESTADO >> "%REPORT%"
echo   -----    ---------                      ------ >> "%REPORT%"
echo   NULL/0   Default (RC4)                  [VULNERABLE] >> "%REPORT%"
echo   4        RC4_HMAC                       [VULNERABLE] >> "%REPORT%"
echo   8        AES128_CTS_HMAC_SHA1           [SEGURO] >> "%REPORT%"
echo   16       AES256_CTS_HMAC_SHA1           [SEGURO] >> "%REPORT%"
echo   24       AES128 + AES256                [SEGURO - RECOMENDADO] >> "%REPORT%"
echo   28       RC4 + AES128 + AES256          [PARCIAL - RC4 presente] >> "%REPORT%"
echo. >> "%REPORT%"

echo. >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo                 RESULTADO FINAL + POC >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo. >> "%REPORT%"

if %TRUST_RC4_FOUND% equ 1 (
    echo   ########################################################### >> "%REPORT%"
    echo   #                                                         # >> "%REPORT%"
    echo   #            *** VULNERABILIDAD PERSISTE ***              # >> "%REPORT%"
    echo   #                                                         # >> "%REPORT%"
    echo   ########################################################### >> "%REPORT%"
    echo. >> "%REPORT%"
    echo   HALLAZGO: Uso de Algoritmos Obsoletos para Kerberos ^(RC4^) >> "%REPORT%"
    echo   ESTADO:   NO REMEDIADO >> "%REPORT%"
    echo. >> "%REPORT%"
    echo   EVIDENCIA: >> "%REPORT%"
    echo   Se identificaron relaciones de confianza ^(Trusts^) utilizando >> "%REPORT%"
    echo   el algoritmo de cifrado RC4 o configuracion Default ^(RC4^). >> "%REPORT%"
    echo   Ver tabla POC anterior para detalle de cada Trust afectado. >> "%REPORT%"
    echo. >> "%REPORT%"
) else (
    echo   ########################################################### >> "%REPORT%"
    echo   #                                                         # >> "%REPORT%"
    echo   #                 *** REMEDIADO ***                       # >> "%REPORT%"
    echo   #                                                         # >> "%REPORT%"
    echo   ########################################################### >> "%REPORT%"
    echo. >> "%REPORT%"
    echo   HALLAZGO: Uso de Algoritmos Obsoletos para Kerberos ^(RC4^) >> "%REPORT%"
    echo   ESTADO:   REMEDIADO >> "%REPORT%"
    echo. >> "%REPORT%"
    echo   EVIDENCIA: >> "%REPORT%"
    echo   Todas las relaciones de confianza ^(Trusts^) utilizan >> "%REPORT%"
    echo   algoritmos de cifrado seguros ^(AES128/AES256^). >> "%REPORT%"
    echo   Ver tabla POC anterior para detalle de cada Trust. >> "%REPORT%"
    echo. >> "%REPORT%"
)

echo. >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo   REMEDIACION ^(si aplica^) >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo. >> "%REPORT%"
echo   Para habilitar AES en un Trust existente ejecutar en AMBOS dominios: >> "%REPORT%"
echo. >> "%REPORT%"
echo   PowerShell: >> "%REPORT%"
echo   Set-ADTrust -Identity "dominio.com" -EncryptionType AES128,AES256 >> "%REPORT%"
echo. >> "%REPORT%"
echo   CMD: >> "%REPORT%"
echo   ksetup /setenctypeattr dominio.com AES256-CTS-HMAC-SHA1-96 AES128-CTS-HMAC-SHA1-96 >> "%REPORT%"
echo. >> "%REPORT%"
echo   IMPORTANTE: Ambos lados del Trust deben soportar y configurar AES >> "%REPORT%"
echo. >> "%REPORT%"

echo. >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo   FIN DEL REPORTE >> "%REPORT%"
echo   Generado: %date% %time% >> "%REPORT%"
echo ============================================================ >> "%REPORT%"

REM ============================================================
REM MOSTRAR RESULTADO EN PANTALLA CON POC
REM ============================================================

echo.
echo ============================================================
echo                 RESULTADO FINAL + POC
echo ============================================================
echo.

REM Mostrar POC en pantalla
type "%POC_FILE%"

echo.

if %TRUST_RC4_FOUND% equ 1 (
    echo   ###########################################################
    echo   #                                                         #
    echo   #            *** VULNERABILIDAD PERSISTE ***              #
    echo   #                                                         #
    echo   ###########################################################
    echo.
    echo   HALLAZGO: Uso de Algoritmos Obsoletos para Kerberos ^(RC4^)
    echo   ESTADO:   NO REMEDIADO
    echo.
    echo   Ver detalle de Trusts afectados en la tabla POC anterior.
) else (
    echo   ###########################################################
    echo   #                                                         #
    echo   #                 *** REMEDIADO ***                       #
    echo   #                                                         #
    echo   ###########################################################
    echo.
    echo   HALLAZGO: Uso de Algoritmos Obsoletos para Kerberos ^(RC4^)
    echo   ESTADO:   REMEDIADO
    echo.
    echo   Todos los Trusts usan cifrado AES.
)

echo.
echo ============================================================
echo   Archivos generados:
echo   - Reporte completo: %REPORT%
echo   - POC Detalle:      %POC_FILE%
echo ============================================================
echo.

pause
