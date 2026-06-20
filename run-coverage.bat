@echo off
set PATH=%USERPROFILE%\apache-maven\apache-maven-3.9.6\bin;%PATH%
set TOTP_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
cd /d "c:\Users\pawan\OneDrive\Desktop\project\distributed-totp-engine"
call mvn test jacoco:report > "%USERPROFILE%\mvn-coverage.txt" 2>&1
echo Exit code: %ERRORLEVEL%
echo.
echo ========= COVERAGE SUMMARY =========
findstr /i "Tests run: BUILD SUCCESS BUILD FAILURE" "%USERPROFILE%\mvn-coverage.txt"
if exist "target\site\jacoco\index.html" (
  echo Coverage report: target\site\jacoco\index.html
) else (
  echo Coverage report was not generated.
)
