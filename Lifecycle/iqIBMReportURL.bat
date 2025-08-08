:: The execution variables are:
echo ================================EXECUTION VARIABLES=================================
SET appName=struts
echo ====================================================================================
setlocal EnableDelayedExpansion

SET fileName=%appName%.json
java -jar C:\Users\Administrator\Downloads\Sonotype\nexus-iq-cli-1.159.0-01.jar -s http://localhost:8070 -a admin:admin123 -t release -r %fileName% -i %appName% .

for /F "delims={}" %%a in (%fileName%) do (
	::set "line=%%~a"
    ::echo "line"
	set value=%%~a
	
	if not "!value:reportHtmlUrl=!"=="!value!" (
		set value=!value:reportHtmlUrl=!
		set value=!value: =!
		set value=!value:":"=!
        set value=!value:"=!
		set value=!value:,=!
		echo Report URL Found:!value!
		set reportURL=!value!
		goto :continue 
	)
)

:continue 
::echo LOOP COMPLETE
echo %reportURL%
echo IQReportLink = %reportURL% >> "%qm_CustomAttributesFile%"
