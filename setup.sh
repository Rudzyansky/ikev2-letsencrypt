#!/usr/bin/sudo bash

#
# Usage
#   ssh vpn 'curl -s https://false.team/ikev2 | sudo bash -s vpn.example.com support@example.com user1 user2'
#
# The credentials will be printed at the end
#
# Tested on
#   Oracle Linux 8.5 (aarch64)
#   CentOS Stream 8 (x86_64)
#
# https://github.com/Rudzyansky/ikev2-letsencrypt
#

yum -yq install https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E '%{rhel}').noarch.rpm
yum -yq install certbot strongswan pwgen

#
# Variables
#

DOMAIN="$1"
E_MAIL="$2"

USERS=(${@:3}) # no spaces in username
PASSW=(`pwgen -s -1 16 "${#USERS[@]}"`)

VPN_SUBNET="172.$(( RANDOM % 16 + 16 )).$(( RANDOM % 256 )).0/24"

DNS=(
	8.8.8.8
	8.8.4.4
)

IKE=(
	aes128-sha256-ecp256
	aes256-sha384-ecp384
	aes128-sha256-modp2048	aes128-sha1-modp2048
	aes256-sha384-modp4096	aes256-sha256-modp4096	aes256-sha1-modp4096
	aes128-sha256-modp1536	aes128-sha1-modp1536
	aes256-sha384-modp2048	aes256-sha256-modp2048	aes256-sha1-modp2048
	aes128-sha256-modp1024	aes128-sha1-modp1024
	aes256-sha384-modp1536	aes256-sha256-modp1536	aes256-sha1-modp1536
	aes256-sha384-modp1024	aes256-sha256-modp1024	aes256-sha1-modp1024
)

ESP=(
	aes128gcm16-ecp256
	aes256gcm16-ecp384
	aes128-sha256-ecp256
	aes256-sha384-ecp384
	aes128-sha256-modp2048	aes128-sha1-modp2048
	aes256-sha384-modp4096	aes256-sha256-modp4096	aes256-sha1-modp4096
	aes128-sha256-modp1536	aes128-sha1-modp1536
	aes256-sha384-modp2048	aes256-sha256-modp2048	aes256-sha1-modp2048
	aes128-sha256-modp1024	aes128-sha1-modp1024
	aes256-sha384-modp1536	aes256-sha256-modp1536	aes256-sha1-modp1536
	aes256-sha384-modp1024	aes256-sha256-modp1024	aes256-sha1-modp1024
	aes128gcm16
	aes256gcm16
	aes128-sha256	aes128-sha1
	aes256-sha384	aes256-sha256	aes256-sha1
)

#
# Network
#

iptables="firewall-cmd --permanent --direct --add-passthrough ipv4"

$iptables -t mangle -I FORWARD -p tcp -m policy --pol ipsec --dir out --syn -m tcpmss --mss 1361:65535 -j TCPMSS --set-mss 1360
$iptables -t mangle -I FORWARD -p tcp -m policy --pol ipsec --dir in --syn -m tcpmss --mss 1361:65535 -j TCPMSS --set-mss 1360
$iptables -A FORWARD -s "$VPN_SUBNET" -d 192.168.0.0/16 -j DROP
$iptables -A FORWARD -s "$VPN_SUBNET" -d 172.16.0.0/12 -j DROP
$iptables -A FORWARD -s "$VPN_SUBNET" -d 10.0.0.0/8 -j DROP

firewall-cmd --permanent --add-service=ipsec
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-masquerade

firewall-cmd --reload

mv /etc/sysctl.conf{,~}

cat << EOF > /etc/sysctl.conf
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
EOF

sysctl -p

#
# Certificates
#

certbot certonly --rsa-key-size 4096 --standalone --agree-tos --no-eff-email --email "$E_MAIL" -d "$DOMAIN"

certsDir="/etc/letsencrypt/live/$DOMAIN"
ipsecDir="/etc/strongswan/ipsec.d"

ln -sf "$certsDir"/fullchain.pem "$ipsecDir"/certs/"$DOMAIN".crt
ln -sf "$certsDir"/privkey.pem "$ipsecDir"/private/"$DOMAIN".key
ln -sf "$certsDir"/chain.pem "$ipsecDir"/cacerts/ca."$DOMAIN".crt

#
# Strongswan
#

SAVEIFS=$IFS;IFS=$','
dns="${DNS[*]}"
ike="${IKE[*]}"
esp="${ESP[*]}"
IFS=$SAVEIFS;unset SAVEIFS

mv /etc/strongswan/ipsec.conf{,~}

cat << EOF > /etc/strongswan/ipsec.conf
# https://wiki.strongswan.org/projects/strongswan/wiki/IpsecConf

config setup
	strictcrlpolicy=yes
	uniqueids=never

conn rw-base
	dpdaction=clear
	dpddelay=30s

conn rw-config
	also=rw-base
	rightsourceip=$VPN_SUBNET
	rightdns=$dns
	leftsubnet=0.0.0.0/0
	leftid=@$DOMAIN
	leftcert=$DOMAIN.crt
	leftsendcert=always
	# not possible with asymmetric authentication
	reauth=no
	rekey=no
	ike=$ike!
	esp=$esp!

conn ikev2-eap-mschapv2
	also=rw-config
	forceencaps=yes
	rightsendcert=never
	rightauth=eap-mschapv2
	eap_identity=%identity
	auto=add
EOF

mv /etc/strongswan/ipsec.secrets{,~}

cat << EOF > /etc/strongswan/ipsec.secrets
: RSA "$DOMAIN.key"
$(for i in "${!USERS[@]}"; do printf '%s : EAP "%s"\n' "${USERS[i]}" "${PASSW[i]}"; done)
EOF

chmod 600 /etc/strongswan/ipsec.secrets

#
# Workaround for: 00[CFG] opening secrets file '/etc/strongswan/ipsec.secrets' failed: Permission denied
#

setsebool -P domain_can_mmap_files on

#
# Certbot renewal service configuring
#

sed -i "/^DEPLOY_HOOK=/s/\"\"/\"--deploy-hook 'strongswan reload'\"/" /etc/sysconfig/certbot

#
# Services
#

systemctl enable --now strongswan-starter
systemctl enable --now certbot-renew.timer

#
# Output
#

cat << EOF
--------------------------------

IKEv2 successfully deployed on $DOMAIN

Credentials:

$(paste -d' ' <(printf '  %s\n' "${USERS[@]}") <(printf '%s\n' "${PASSW[@]}") | column -t -s' ')

If you need CAs (e.g. RouterOS)
https://letsencrypt.org/certs/isrgrootx1.pem
https://letsencrypt.org/certs/lets-encrypt-r3.pem

EOF
