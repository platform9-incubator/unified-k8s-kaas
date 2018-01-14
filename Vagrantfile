
Vagrant.configure("2") do |config|
  config.vm.box = "bento/centos-7.4"
  config.vm.provider "virtualbox" do |vb|
     vb.memory = "512"
   end
   config.vm.synced_folder ".", "/home/vagrant/go/src/single-rbac"
   config.vm.provision "shell", inline: <<-SHELL
     sudo yum -y install git
     sudo yum -y install go
     sudo yum -y install docker 
     sudo systemctl enable docker
     sudo systemctl start docker
     sudo chmod 777 /var/run/docker.sock

     curl -LO https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl
     chmod +x ./kubectl
     sudo mv ./kubectl /usr/local/bin/kubectl

     cd /home/vagrant
     git clone https://github.com/OpenVPN/easy-rsa.git
     cp /home/vagrant/go/src/single-rbac/both /home/vagrant/easy-rsa/easyrsa3/x509-types
     
   SHELL
end
