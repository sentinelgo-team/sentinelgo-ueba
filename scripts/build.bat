@echo off
REM SentinelGo Build Script for Windows
REM Usage: scripts\build.bat

set BINARY_NAME=sentinelgo.exe
set VERSION=1.0.0
set BUILD_DIR=build

echo.
echo ======================================
echo   Building SentinelGo v%VERSION%
echo ======================================
echo.

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo [1/4] Downloading dependencies...
go mod tidy
if %errorlevel% neq 0 (
    echo ERROR: Failed to download dependencies
    exit /b 1
)

echo [2/4] Running tests...
go test ./... -count=1 -timeout 60s
if %errorlevel% neq 0 (
    echo ERROR: Tests failed
    exit /b 1
)

echo [3/4] Running vet...
go vet ./...
if %errorlevel% neq 0 (
    echo WARNING: go vet found issues
)

echo [4/4] Building binary...
go build -ldflags "-X main.version=%VERSION%" -o %BUILD_DIR%\%BINARY_NAME% ./cmd/sentinelgo/
if %errorlevel% neq 0 (
    echo ERROR: Build failed
    exit /b 1
)

echo.
echo ======================================
echo   Build successful: %BUILD_DIR%\%BINARY_NAME%
echo ======================================
echo.

%BUILD_DIR%\%BINARY_NAME% version
