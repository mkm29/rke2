# RKE2 Installation on Rocky Linux 8

## Prerequisites

After provisioing the VM in Hyper-V, first set a static IP:

```console
sudo vi /etc/sysconfig/network-scripts/ifcfg-eth0
```

- Change `BOOTPROTO` to `static`
- Change `IPV6_ADDR_GEN_MODE` to `stable-privacy`
- Set `IPADDR` to your static IP (eg. `192.168.7.1`)
- Set `PREFIX` to your subnet mask (eg. `22`)
- Set `GATEWAY` to your gateway (eg. `192.168.4.1`)
- Set `DNS1` to your DNS server (eg. `192.168.6.1`)
- Set `DNS2` to Google's DNS server: `8.8.8.8`

```console
sudo su -
sed -i 's/BOOTPROTO=dhcp/BOOTPROTO=static/g' /etc/sysconfig/network-scripts/ifcfg-eth0
sed -i 's/IPV6_ADDR_GEN_MODE=/IPV6_ADDR_GEN_MODE=stable-privacy/g' /etc/sysconfig/network-scripts/ifcfg-eth0

cat <<EOF >> /etc/sysconfig/network-scripts/ifcfg-eth0
IPADDR=192.168.7.1
PREFIX=22
GATEWAY=192.168.4.1
DNS1=192.168.6.1
DNS2=8.8.8.8
EOF
```

Restart the network service:

```console
sudo systemctl restart NetworkManager
```

### swap

Disable swap:

```console
sudo swapoff -a
sudo sed -e '/swap/s/^/#/g' -i /etc/fstab
```

Reload the systemd daemon:

```console
sudo systemctl daemon-reload
```

Finally reboot.

### iptables configuration

Since we will be using cilium as the CNI (using eBPF), we will not be usin g iptables at all. 

```console
sudo modprobe br_netfilter
cat <<EOT | sudo tee /etc/modules-load.d/kubernetes.conf
br_netfilter
EOT
cat <<EOT | sudo tee /etc/sysctl.d/kubernetes.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
EOT
sudo sysctl --system
```

### selinux

Before installing kubernetes you need to configure SELinux, so it is compatible with the current kubernetes version. Basically what it needs to do is do disable SELinux, this is required so pods can access the filesystem, which parts of the kubernetes pods require.

```console
sudo setenforce 0
sudo sed -i 's/^SELINUX=enforcing$/SELINUX=permissive/' /etc/selinux/config
```

### Firewall rules

Certain ports must be allowed through the firewall:

```console
sudo firewall-cmd --add-port=9345/tcp --permanent
sudo firewall-cmd --add-port=6443/tcp --permanent
sudo firewall-cmd --add-port=10250/tcp --permanent
sudo firewall-cmd --add-port=2379/tcp --permanent
sudo firewall-cmd --add-port=2380/tcp --permanent
sudo firewall-cmd --add-port=30000-32767/tcp --permanent
# Used for the Rancher Monitoring
sudo firewall-cmd --add-port=9796/tcp --permanent
sudo firewall-cmd --add-port=19090/tcp --permanent
# For cockpit
sudo firewall-cmd --add-port=9090/tcp --permanent
sudo firewall-cmd --add-port=6942/tcp --permanent
sudo firewall-cmd --add-port=9091/tcp --permanent
### CNI specific ports
# 4244/TCP is required when the Hubble Relay is enabled and therefore needs to connect to all agents to collect the flows
sudo firewall-cmd --add-port=4244/tcp --permanent

# for cilium connectivity test
ALLOWED_PORTS=( 8080 4245 )
for i in "${ALLOWED_PORTS[@]}"
do
  sudo firewall-cmd --add-port=$i/tcp --permanent
done

# Cilium healthcheck related permits:
sudo firewall-cmd --add-port=4240/tcp --permanent
sudo firewall-cmd --remove-icmp-block=echo-request --permanent
sudo firewall-cmd --remove-icmp-block=echo-reply --permanent
# Since we are using Cilium with GENEVE as overlay, we need the following port too:
sudo firewall-cmd --add-port=6081/udp --permanent
### Ingress Controller specific ports
sudo firewall-cmd --add-port=80/tcp --permanent
sudo firewall-cmd --add-port=443/tcp --permanent
### To get DNS resolution working, simply enable Masquerading.
sudo firewall-cmd --zone=public  --add-masquerade --permanent

### Finally apply all the firewall changes
sudo firewall-cmd --reload
```

### Kernel

In order for Cilium to operate properly (eBPF), the kernel must be updated to at least version 4.19:

```console
sudo dnf -y upgrade --refresh
sudo rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
sudo dnf install https://www.elrepo.org/elrepo-release-8.el8.elrepo.noarch.rpm -y
# sudo dnf --enablerepo=elrepo-kernel install kernel-ml
sudo dnf --enablerepo=elrepo-kernel install -y kernel-ml kernel-ml-core kernel-ml-headers kernel-ml-modules kernel-ml-modules-extra
```

You need to reboot the VM to boot into the new kernel:

```console
sudo reboot now
```

### Longhorn

Install required packages:

```console
# yum install -y epel-release
sudo yum install -y nano curl wget git tmux jq vim-common iscsi-initiator-utils
sudo modprobe iscsi_tcp

# must switch to root user: sudo su -
sudo echo "iscsi_tcp" >/etc/modules-load.d/iscsi-tcp.conf
sudo systemctl enable iscsid --now
sudo systemctl start iscsid

cat <<EOF>> /etc/NetworkManager/conf.d/rke2-canal.conf
[keyfile]
unmanaged-devices=interface-name:cali*;interface-name:flannel*
EOF
systemctl reload NetworkManager
```

### RKE2 Installation

```console
VERSION=$(curl -s https://api.github.com/repos/rancher/rke2/releases/latest | jq -r .tag_name)
curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL=latest INSTALL_RKE2_VERSION="$VERSION" sh -

# systemctl enable rke2-server.service --now
# systemctl start rke2-server.service
```

### Kubectl, Helm, and Longhorn

```console
sudo git clone https://github.com/ahmetb/kubectx /opt/kubectx
sudo ln -s /opt/kubectx/kubectx /usr/local/bin/kubectx
sudo ln -s /opt/kubectx/kubens /usr/local/bin/kubens
echo 'PATH=$PATH:/usr/local/bin' >> /etc/profile
echo 'PATH=$PATH:/var/lib/rancher/rke2/bin' >> /etc/profile
source /etc/profile

curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3
chmod +x get_helm.sh
./get_helm.sh
rm get_helm.sh
```

### RKE2 Configuration

**Control plane**

```console
mkdir -p /etc/rancher/rke2
cat << EOF >  /etc/rancher/rke2/config.yaml
write-kubeconfig-mode: "0644"
# profile: "cis-1.5"
selinux: true
# add ips/hostname of hosts and loadbalancer
tls-san:
  - "controlplane1.kubula.internal"
  - "192.168.7.1"
# Make a etcd snapshot every 6 hours
# etcd-snapshot-schedule-cron: " */6 * * *"
# Keep 56 etcd snapshorts (equals to 2 weeks with 6 a day)
# etcd-snapshot-retention: 56
cni:
  - cilium
disable:
  - rke2-canal
  - rke2-kube-proxy
# network:
#   plugin: none
disable-kube-proxy: true
EOF

# must be switched to root user: sudo su -
echo "exclude=rke2-*" >> /etc/dnf/dnf.conf
```


Now you can start/enable the RKE2 service:

```console
systemctl enable rke2-server.service --now
```

Check status:

```console
sudo systemctl status rke2-server.service
sudo journalctl -u rke2-server.service -f
```

#### Configure kubectl

```console
mkdir ~/.kube
sudo cp /etc/rancher/rke2/rke2.yaml ~/.kube/config
sudo chown $(id -u):$(id -g) ~/.kube/config
chmod 600 ~/.kube/config

sudo cp /var/lib/rancher/rke2/bin/kubectl /usr/local/bin
sudo chown $(id -u):$(id -g) /usr/local/bin/kubectl
```

### Cilium

#### Install CLI

```console
CILIUM_CLI_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/cilium-cli/main/stable.txt)
CLI_ARCH=arm64
if [ "$(uname -m)" = "aarch64" ]; then CLI_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/cilium-cli/releases/download/${CILIUM_CLI_VERSION}/cilium-darwin-${CLI_ARCH}.tar.gz{,.sha256sum}
sha256sum --check cilium-linux-${CLI_ARCH}.tar.gz.sha256sum
sudo tar xzvfC cilium-linux-${CLI_ARCH}.tar.gz /usr/local/bin
rm cilium-linux-${CLI_ARCH}.tar.gz{,.sha256sum}
```

#### Deploy Cilium

**Note** using the Halm method (in `/var/lib/rancher/rke2/server/manifests`) results in issues with the CNI, as in it does not install the binary in `/opt/cni/bin`. Therefore, it is better to do this:

```console
git clone https://github.com/cilium/cilium.git
cd cilium
cilium install --chart-directory ./install/kubernetes/cilium
cilium status --wait
```

#### Hubble

In order to enable Hubble, run the command: `cilium hubble enable`.

Install the Hubble CLI:

```console
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
HUBBLE_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then HUBBLE_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
sha256sum --check hubble-linux-${HUBBLE_ARCH}.tar.gz.sha256sum
sudo tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin
rm hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
```

### Agents

Follow the same steps as above, but instead of `rke2-server.service` use `rke2-agent.service`.

#### Install RKE2

```console
VERSION=$(curl -s https://api.github.com/repos/rancher/rke2/releases/latest | jq -r .tag_name)
curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL=latest INSTALL_RKE2_TYPE="agent" sh -

# change the ip to reflect your rancher1 ip
MASTER_IP=192.168.7.1
echo "server: https://$MASTER_IP:9345" > /etc/rancher/rke2/config.yaml

# change the Token to the one from rancher1 /var/lib/rancher/rke2/server/node-token
echo "token: $TOKEN" >> /etc/rancher/rke2/config.yaml

cat <<EOF > 05-cilium.conflist

  "cniVersion": "0.3.1",
  "name": "cilium",
  "plugins": [
    {
       "type": "cilium-cni",
       "enable-debug": false,
       "log-file": "/var/run/cilium/cilium-cni.log"
    }
  ]
}
EOF

WORKER1=192.168.7.2
# scp the cilium binaries from rancher1 to /opt/cni/bin
# From MASTER
# scp /opt/cni/bin/cilium-cni worker@WORKER1:/opt/cni/bin

# enable and start
systemctl enable rke2-agent.service --now
systemctl start rke2-agent.service
```

_Note_: for some reason after enabling Cilium I cannot have a coreDNS pod running on the controlplane. Cordon it and restart the deployment (for now, until I figure out what is causing this).

### MetalLB

Install:

```console
helm upgrade --install metallb metallb/metallb --create-namespace \
    --namespace metallb-system --wait
```

```console
cat << 'EOF' | kubectl apply -f -
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: default-pool
  namespace: metallb-system
spec:
  addresses:
  - 192.168.7.10-192.168.7.250
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: default
  namespace: metallb-system
spec:
  ipAddressPools:
  - default-pool
EOF
```

### ArgoCD

```console
kubectl patch service argocd-server -n argocd --patch '{ "spec": { "type": "LoadBalancer", "loadBalancerIP": "192.168.7.11" } }'
```

Go to the UI and login with the default credentials (admin) and password:

```console
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d; echo
```

You should then change your password and delete the secret. Now just use Argo to install charts. 

More to follow on installing these charts (via ArgoCD):

- Prometheus Stack
- Loki
- Minio
- Grafana
- PostgresQL-HA (Bitnami)
- Keycloak
- Harbor
- Rancher
- Longhorn
- KubeVirt
- KubeArmor
- Fission
- Knative
- Argo Workflows
- Argo Events
- Falco
- Trivy
- Elasticsearch
- Kibana
- Fluentbit
- Promtail
- KubeStateMetrics
- NodeExporter
- Thanos
- CertManager
- Nginx Ingress Controller
- OpenEBS
