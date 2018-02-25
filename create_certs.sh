export PATH=$PATH:$PWD/easy-rsa/easyrsa3/
rm -rf certs
mkdir certs
cd certs
mkdir client proxy apiserver 
cd client
easyrsa init-pki
easyrsa --batch --req-cn=client-ca build-ca nopass
#example admin user
easyrsa --batch --req-cn=usera --req-email= --dn-mode=org --req-org=system:masters gen-req usera nopass
easyrsa --batch sign-req client usera
#example limited access user
easyrsa --batch --req-cn=userb --req-email= --dn-mode=org --req-org=test gen-req userb nopass
easyrsa --batch sign-req client userb
cd ../proxy
easyrsa init-pki
easyrsa --batch --req-cn=proxy-ca build-ca nopass
easyrsa --batch --req-cn=proxy --req-org=proxy --req-email= --dn-mode=org  --subject-alt-name=DNS:localhost,IP:127.0.0.1,IP:10.0.2.15 gen-req proxy nopass
easyrsa --batch --subject-alt-name=DNS:localhost,IP:127.0.0.1,IP:10.0.2.15 sign-req both proxy nopass
cd ../apiserver
easyrsa init-pki
easyrsa --batch --req-cn=apiserver-ca build-ca nopass
easyrsa --batch --req-cn=apiserver --req-org=apiserver --req-email= --dn-mode=org  --subject-alt-name=DNS:localhost,IP:127.0.0.1,IP:10.0.2.15 gen-req apiserver nopass
easyrsa --batch --subject-alt-name=DNS:localhost,IP:127.0.0.1,IP:10.0.2.15 sign-req server apiserver nopass
