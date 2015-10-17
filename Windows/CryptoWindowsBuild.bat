call "CryptoWindowsDeconstruct.bat"

cd ..

copy "%cd%\Windows\CryptoGateway.vcxproj" "%cd%\CryptoGateway.vcxproj"
copy "%cd%\Windows\CryptoGateway.vcxproj.filters" "%cd%\CryptoGateway.vcxproj.filters"
copy "%cd%\Windows\CryptoGateway.vcxproj.user" "%cd%\CryptoGateway.vcxproj.user"

cd Windows