@echo off
REM ============================================================
REM Script: Verificar_RC4_Kerberos.bat
REM Descripcion: Audita el uso de algoritmos debiles (RC4/DES) en Kerberos
REM Ejecutar como Administrador en un Domain Controller
REM ============================================================

setlocal enabledelayedexpansion

echo.
echo ============================================================
echo   AUDITORIA DE CIFRADO KERBEROS - RC4/DES
echo   Fecha: %date% %time%
echo ============================================================
echo.

REM Crear carpeta de salida
set "OUTPUT_DIR=C:\temp\Kerberos_Audit"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

set "REPORT=%OUTPUT_DIR%\Reporte_RC4_Kerberos_%date:~-4%%date:~3,2%%date:~0,2%.txt"
set "CSV_USERS=%OUTPUT_DIR%\Usuarios_Cifrado.csv"
set "CSV_COMPUTERS=%OUTPUT_DIR%\Computadoras_Cifrado.csv"
set "LDIF_USERS=%OUTPUT_DIR%\Usuarios_EncryptionTypes.ldf"
set "LDIF_COMPUTERS=%OUTPUT_DIR%\Computadoras_EncryptionTypes.ldf"

echo Generando reporte en: %OUTPUT_DIR%
echo.

REM ============================================================
REM INICIO DEL REPORTE
REM ============================================================

echo ============================================================ > "%REPORT%"
echo   REPORTE DE AUDITORIA - CIFRADO KERBEROS RC4/DES >> "%REPORT%"
echo   Fecha de ejecucion: %date% %time% >> "%REPORT%"
echo   Equipo: %COMPUTERNAME% >> "%REPORT%"
echo   Dominio: %USERDNSDOMAIN% >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo. >> "%REPORT%"

REM ============================================================
REM 1. EXPORTAR USUARIOS CON msDS-SupportedEncryptionTypes
REM ============================================================

echo [1/6] Exportando usuarios con tipos de cifrado...
echo. >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"
echo 1. USUARIOS CON msDS-SupportedEncryptionTypes >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"

ldifde -f "%LDIF_USERS%" -d "%USERDNSDOMAIN%" -r "(&(objectClass=user)(objectCategory=person))" -l "sAMAccountName,distinguishedName,msDS-SupportedEncryptionTypes,userAccountControl" -p subtree 2>nul

if exist "%LDIF_USERS%" (
    echo Exportado: %LDIF_USERS% >> "%REPORT%"
    echo Usuarios exportados correctamente.
) else (
    echo ERROR: No se pudo exportar usuarios >> "%REPORT%"
    echo ERROR: No se pudo exportar usuarios.
)

REM ============================================================
REM 2. EXPORTAR COMPUTADORAS CON msDS-SupportedEncryptionTypes
REM ============================================================

echo [2/6] Exportando computadoras con tipos de cifrado...
echo. >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"
echo 2. COMPUTADORAS CON msDS-SupportedEncryptionTypes >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"

ldifde -f "%LDIF_COMPUTERS%" -d "%USERDNSDOMAIN%" -r "(objectClass=computer)" -l "sAMAccountName,distinguishedName,msDS-SupportedEncryptionTypes,userAccountControl" -p subtree 2>nul

if exist "%LDIF_COMPUTERS%" (
    echo Exportado: %LDIF_COMPUTERS% >> "%REPORT%"
    echo Computadoras exportadas correctamente.
) else (
    echo ERROR: No se pudo exportar computadoras >> "%REPORT%"
    echo ERROR: No se pudo exportar computadoras.
)

REM ============================================================
REM 3. BUSCAR CUENTAS CON DES HABILITADO (UAC flag 2097152)
REM ============================================================

echo [3/6] Buscando cuentas con DES habilitado (USE_DES_KEY_ONLY)...
echo. >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"
echo 3. CUENTAS CON FLAG USE_DES_KEY_ONLY (UAC 2097152) >> "%REPORT%"
echo    CRITICO: Estas cuentas usan cifrado DES obsoleto >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"

dsquery * -filter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))" -attr sAMAccountName distinguishedName 2>nul >> "%REPORT%"

if %errorlevel% equ 0 (
    echo Busqueda completada. >> "%REPORT%"
) else (
    echo No se encontraron cuentas con DES habilitado o error en consulta. >> "%REPORT%"
)

REM ============================================================
REM 4. VERIFICAR CONFIGURACION DE REGISTRO (CIFRADO KERBEROS)
REM ============================================================

echo [4/6] Verificando configuracion de registro...
echo. >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"
echo 4. CONFIGURACION DE REGISTRO - KERBEROS >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"

echo. >> "%REPORT%"
echo Clave: HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters >> "%REPORT%"
echo ----------------------------------------------------------------------- >> "%REPORT%"
reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" 2>nul >> "%REPORT%"
if %errorlevel% neq 0 (
    echo [INFO] Clave no existe o sin valores configurados >> "%REPORT%"
)

echo. >> "%REPORT%"
echo Clave: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters >> "%REPORT%"
echo --------------------------------------------------------------------------------------- >> "%REPORT%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" 2>nul >> "%REPORT%"
if %errorlevel% neq 0 (
    echo [INFO] Clave no existe o sin valores configurados (GPO no aplicada) >> "%REPORT%"
)

REM ============================================================
REM 5. BUSCAR CUENTAS CON RC4 SOLAMENTE (Valor 4)
REM ============================================================

echo [5/6] Buscando cuentas con solo RC4 configurado...
echo. >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"
echo 5. CUENTAS CON msDS-SupportedEncryptionTypes = 4 (SOLO RC4) >> "%REPORT%"
echo    CRITICO: Estas cuentas solo soportan RC4 >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"

dsquery * -filter "(&(objectCategory=person)(objectClass=user)(msDS-SupportedEncryptionTypes=4))" -attr sAMAccountName distinguishedName msDS-SupportedEncryptionTypes 2>nul >> "%REPORT%"

echo. >> "%REPORT%"
echo Buscando valores comunes con RC4 habilitado (4, 7, 20, 23, 28): >> "%REPORT%"
echo. >> "%REPORT%"

for %%V in (4 7 20 23 28) do (
    echo --- Valor %%V --- >> "%REPORT%"
    dsquery * -filter "(&(objectCategory=person)(objectClass=user)(msDS-SupportedEncryptionTypes=%%V))" -attr sAMAccountName 2>nul >> "%REPORT%"
)

REM ============================================================
REM 6. RESUMEN DE TIPOS DE CIFRADO
REM ============================================================

echo [6/6] Generando resumen...
echo. >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"
echo 6. REFERENCIA DE VALORES msDS-SupportedEncryptionTypes >> "%REPORT%"
echo ------------------------------------------------------------ >> "%REPORT%"
echo. >> "%REPORT%"
echo   VALORES Y SU SIGNIFICADO: >> "%REPORT%"
echo   ========================= >> "%REPORT%"
echo   0x01 (1)  = DES_CBC_CRC           [DEBIL - OBSOLETO] >> "%REPORT%"
echo   0x02 (2)  = DES_CBC_MD5           [DEBIL - OBSOLETO] >> "%REPORT%"
echo   0x04 (4)  = RC4_HMAC              [DEBIL - VULNERABLE] >> "%REPORT%"
echo   0x08 (8)  = AES128_CTS_HMAC_SHA1  [FUERTE] >> "%REPORT%"
echo   0x10 (16) = AES256_CTS_HMAC_SHA1  [FUERTE] >> "%REPORT%"
echo. >> "%REPORT%"
echo   VALORES COMUNES: >> "%REPORT%"
echo   ================ >> "%REPORT%"
echo   4  = Solo RC4                     [VULNERABLE] >> "%REPORT%"
echo   7  = DES + RC4                    [VULNERABLE] >> "%REPORT%"
echo   24 = AES128 + AES256              [SEGURO] >> "%REPORT%"
echo   28 = RC4 + AES128 + AES256        [PARCIAL - RC4 presente] >> "%REPORT%"
echo   31 = DES + RC4 + AES128 + AES256  [VULNERABLE - tiene DES] >> "%REPORT%"
echo. >> "%REPORT%"
echo   RECOMENDACION: >> "%REPORT%"
echo   ============== >> "%REPORT%"
echo   - Valor ideal: 24 (solo AES128 + AES256) >> "%REPORT%"
echo   - Eliminar RC4 de todas las cuentas >> "%REPORT%"
echo   - Eliminar DES de todas las cuentas >> "%REPORT%"
echo. >> "%REPORT%"

REM ============================================================
REM FINALIZAR
REM ============================================================

echo. >> "%REPORT%"
echo ============================================================ >> "%REPORT%"
echo   FIN DEL REPORTE >> "%REPORT%"
echo   Archivos generados en: %OUTPUT_DIR% >> "%REPORT%"
echo ============================================================ >> "%REPORT%"

echo.
echo ============================================================
echo   AUDITORIA COMPLETADA
echo ============================================================
echo.
echo Archivos generados:
echo   - Reporte:     %REPORT%
echo   - LDIF Users:  %LDIF_USERS%
echo   - LDIF Comps:  %LDIF_COMPUTERS%
echo.
echo Revisa el archivo LDIF para buscar cuentas con valores:
echo   - msDS-SupportedEncryptionTypes: 4 (solo RC4)
echo   - msDS-SupportedEncryptionTypes: 7 (DES + RC4)
echo   - msDS-SupportedEncryptionTypes: 28 (RC4 + AES)
echo.
echo Si NO hay cuentas con valores 1-7 = REMEDIADO
echo Si hay cuentas con valores 1-7 = VULNERABLE
echo.

pause
