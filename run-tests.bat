@echo off
set PATH=%USERPROFILE%\apache-maven\apache-maven-3.9.6\bin;%PATH%
set TOTP_ENCRYPTION_KEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
cd /d "c:\Users\pawan\OneDrive\Desktop\project\distributed-totp-engine"
call mvn test > "%USERPROFILE%\mvn-test.txt" 2>&1
echo Exit code: %ERRORLEVEL%
echo.
echo ========= TEST SUMMARY =========
findstr /i "Tests run: BUILD SUCCESS BUILD FAILURE Failures: FAILURE" "%USERPROFILE%\mvn-test.txt"
