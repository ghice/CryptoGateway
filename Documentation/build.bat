::Builds the documentation for this library
@echo off
setlocal

cd ..
cd ..

IF NOT EXIST Datastructures GOTO ERROR
cd Datastructures
IF NOT EXIST Windows GOTO ERROR
cd Windows
call buildDocumentation.bat CryptoGateway
goto END
:ERROR
echo Could not find buildDocumentation.bat
:END

endlocal