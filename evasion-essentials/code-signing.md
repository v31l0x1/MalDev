# Binary Signature

{% code overflow="wrap" %}
```powershell
# Generate Cert
makecert -r -pe -n "CN = Microsoft Root Certificate Authority 2010,O = Microsoft Corperation,L = Redmond,S = Washington,C = US" -ss CA -sr CurrentUser -a sha256 -cy authority -sky signature -sv CA.pvk CA.cer

# Generate another cert with previously generated cert
makecert -pe -n "CN = Microsoft Root Certificate Authority 2010,O = Microsoft Corperation,L = Redmond,S = Washington,C = US" -a sha256 -cy end -sky signature -eku 1.3.6.1.5.5.7.3.3,1.3.6.1.4.1.311.10.3.24,1.3.6.1.4.1.311.10.3.6 -ic CA.cer -iv CA.pvk -sv SPC.pvk SPC.cer

# Convert the previously generated cert
pvk2pfx -pvk SPC.pvk -spc SPC.cer -pfx SPC.pfx

# Finally sign the binary
signtool sign /v /fd SHA256 /f SPC.pfx ShellcodeRunner.exe
```
{% endcode %}

