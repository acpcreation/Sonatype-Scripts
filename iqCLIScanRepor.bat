@echo off
setlocal EnableDelayedExpansion

@REM UPDATE WITH FILE NAME
SET appId=%1
SET target=%2

SET fileName=%appId%-results.json

echo  === IQ CLI SCAN COMMAND ===
java -jar nexus-iq-cli-1.160.0-01.jar -s https://iq.aplattel.ngrok.io/ -a admin:admin^^!23 -t build -i %appId% -r %fileName% %target%

@REM PARSE SONATYPE CLI OUTPUT FILE
@REM SET found=False
rem Read the lines of JSon file, removing braces
for /F "delims={}" %%a in (%fileName%) do (
    set "line=%%~a"
    @REM echo "line"
    rem Process each pair of "variable": "string" values
    for %%b in ("!line:": "==!") do (
        SET value=%%b
        @REM echo !value!

        @REM if !found!==True (
        @REM     set value=!value:"=!
        @REM     set value=!value:,=!
        @REM     set value=!value: =!
        @REM     set value=!value::=!
        @REM     set value=!value:reportHtmlUrl=!
        @REM     echo !value!
        @REM     @REM echo Done
        @REM     exit
        @REM )

        @REM Check if field is reportHtmlUrl
        if not "!value:reportHtmlUrl=!"=="!value!" (
            @REM SET found=True
            
            set value=!value:"=!
            set value=!value:,=!
            set value=!value: =!
            set value=!value::=!
            set value=!value:reportHtmlUrl=!
            echo !value!
            exit
        )   
    )
)
