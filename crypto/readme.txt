rem see http://woshub.com/how-to-sign-an-unsigned-driver-for-windows-7-x64/

cd "Z:\installs\ewdk\Program Files\Windows Kits\10\bin\x64"

makecert -r -sv z:\wdrbd9\crypto\linbit.pvk -n CN=LINBIT z:\wdrbd9\crypto\linbit.cer
rem password was "a"

cert2spc.exe z:\wdrbd9\crypto\linbit.cer z:\wdrbd9\crypto\linbit.spc


pvk2pfx -pvk z:\wdrbd9\crypto\linbit.pvk -pi a -spc z:\wdrbd9\crypto\linbit.spc -pfx z:\wdrbd9\crypto\linbit.pfx -po a

update: create pvk from pem using:

openssl rsa -in linbit-ha-code-signing_no_pw.pem -outform PVK -pvk-strong -out linbit.pvk

(openssl should be installed on Linux)

update: cert manager has to be run manually (usually double clicking the crt file adds it to the system)
