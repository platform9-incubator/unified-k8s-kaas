#Cleanup
docker stop etcd
docker rm etcd

docker stop apiserver
docker rm apiserver

docker stop cm
docker rm cm

#Start new
docker run --net=host --name=etcd  --detach quay.io/coreos/etcd 
docker run --net=host --name=apiserver --detach \
                                --volume=$PWD/certs/proxy/pki/ca.crt:/tmp/client_ca.crt  \
                                --volume=$PWD/certs/apiserver/pki/private/apiserver.key:/tmp/server.key \
                                --volume=$PWD/certs/apiserver/pki/issued/apiserver.crt:/tmp/server.crt \
                                gcr.io/google-containers/hyperkube:v1.8.6  /hyperkube apiserver \
                                --etcd-servers=http://127.0.0.1:2379 --service-cluster-ip-range=10.0.0.0/16  \
                                --requestheader-username-headers=X-Remote-User \
                                --requestheader-group-headers=X-Remote-Group \
                                --anonymous-auth=false \
                                --insecure-port=8081 --authorization-mode=RBAC \
                                --client-ca-file=/tmp/client_ca.crt \
                                --requestheader-client-ca-file=/tmp/client_ca.crt \
                                --tls-cert-file=/tmp/server.crt \
                                --tls-private-key-file=/tmp/server.key

docker run --net=host --name=cm --volume=$PWD/certs/apiserver/pki/ca.crt:/tmp/ca.crt  \
                                --volume=$PWD/certs/apiserver/pki/private/ca.key:/tmp/ca.key \
                                --detach gcr.io/google-containers/hyperkube:v1.8.6 \
                                /hyperkube controller-manager --master=http://127.0.0.1:8081 \
                                --cluster-signing-cert-file=/tmp/ca.crt \
                                --cluster-signing-key-file=/tmp/ca.key
