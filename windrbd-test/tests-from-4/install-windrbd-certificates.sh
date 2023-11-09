curl https://nexus.at.linbit.com/repository/windows/WinDRBD/linbit-trusted-cert.cer > linbit-trusted-cert.cer
certutil -addstore -f root linbit-trusted-cert.cer
certutil -addstore "TrustedPublisher" linbit-trusted-cert.cer
curl https://nexus.at.linbit.com/repository/windows/WinDRBD/linbit-self-signed-cert.cer > linbit-self-signed-cert.cer
certutil -addstore -f root linbit-self-signed-cert.cer
certutil -addstore "TrustedPublisher" linbit-self-signed-cert.cer
