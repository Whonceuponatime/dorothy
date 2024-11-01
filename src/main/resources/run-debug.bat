@echo on
set JAVA_OPTS=-Dlog4j.debug=true
dorothy.exe > debug.log 2>&1
pause 