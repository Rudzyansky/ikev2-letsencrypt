#!/usr/bin/sudo bash

#
# Usage
#   ssh vpn 'curl -sL https://false.team/ikev2 | sudo bash -s vpn.example.com support@example.com user1 user2'
#
# The credentials will be printed at the end
#
# Attention: Untested
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

# Allowed values: stroke, vici
CONF_TYPE='vici'

CONF_DIR='/etc/strongswan'
CERTS_DIR="/etc/letsencrypt/live/$DOMAIN"

USERS=(${@:3}) # no spaces in username
PASSW=($(pwgen -s -1 16 "${#USERS[@]}"))

VPN_SUBNET="172.$(( RANDOM % 16 + 16 )).$(( RANDOM % 256 )).0/24"

DNS=(
	9.9.9.9
	149.112.112.112
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

TMP_IFS=$IFS; IFS=$','

dns="${DNS[*]}"
ike="${IKE[*]}"
esp="${ESP[*]}"

IFS=$TMP_IFS; unset TMP_IFS

#
# Workaround for: 00[CFG] opening secrets file '/etc/strongswan/ipsec.secrets' failed: Permission denied
#

setsebool -P domain_can_mmap_files on

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
# Setup renew hook for certbot service
#

touch "$CONF_DIR"/reload-certs.sh
chmod 755 "$CONF_DIR"/reload-certs.sh
sed -re 's|^(DEPLOY_HOOK)=".*"$|\1="--deploy-hook /etc/strongswan/reload-certs.sh"|' -i /etc/sysconfig/certbot

#
# Certificates
#

certbot certonly --rsa-key-size 4096 --standalone --agree-tos --no-eff-email --email "$E_MAIL" -d "$DOMAIN"

#
# Creating secrets file
#

mv "$CONF_DIR"/ipsec.secrets{,~}
touch "$CONF_DIR"/ipsec.secrets
chmod 600 "$CONF_DIR"/ipsec.secrets
cat << EOF > "$CONF_DIR"/ipsec.secrets
$(for i in "${!USERS[@]}"; do printf '%s : EAP "%s"\n' "${USERS[i]}" "${PASSW[i]}"; done)
EOF

#
# Stroke configuration style
#

function stroke_conf {
	# Certificates
	ln -sf "$CERTS_DIR"/chain.pem     "$CONF_DIR"/ipsec.d/cacerts/"$DOMAIN"
	ln -sf "$CERTS_DIR"/fullchain.pem "$CONF_DIR"/ipsec.d/certs/"$DOMAIN"
	ln -sf "$CERTS_DIR"/privkey.pem   "$CONF_DIR"/ipsec.d/private/"$DOMAIN"

	# Strongswan
	mv "$CONF_DIR"/ipsec.conf{,~}
	cat << EOF > "$CONF_DIR"/ipsec.conf
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
	leftcert=$DOMAIN
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

	# Secrets
	echo ": RSA $DOMAIN" >> "$CONF_DIR"/ipsec.secrets

	# Setup renew hook for certbot service
	cat << EOF > "$CONF_DIR"/reload-certs.sh
#!/bin/sh

strongswan purgecerts
strongswan rereadall
EOF

	# Service
	systemctl enable --now strongswan-starter
}

#
# Vici configuration style
#

function vici_conf {
	# Certificates
	ln -sf "$CERTS_DIR"/chain.pem     "$CONF_DIR"/swanctl/x509ca/"$DOMAIN"
	ln -sf "$CERTS_DIR"/fullchain.pem "$CONF_DIR"/swanctl/x509/"$DOMAIN"
	ln -sf "$CERTS_DIR"/privkey.pem   "$CONF_DIR"/swanctl/private/"$DOMAIN"

	# Strongswan
	mv "$CONF_DIR"/swanctl/swanctl.conf{,~}
	cat << EOF > "$CONF_DIR"/swanctl/swanctl.conf
# https://docs.strongswan.org/docs/5.9/swanctl/swanctlConf.html
# https://wiki.strongswan.org/projects/strongswan/wiki/Fromipsecconf

connections {
	rw-eap-mschapv2 {
		version = 2
		unique = never
		local {
			auth = pubkey
			certs = $DOMAIN
			id = @$DOMAIN
		}
		remote {
			auth = eap-mschapv2
			eap_id = %any
			revocation = strict
		}
		send_cert = always
		send_certreq = no
		children {
			net {
				local_ts = 0.0.0.0/0
				esp_proposals = $esp
			}
		}
		proposals = $ike
		encap = yes
		pools = virtual
	}
}

pools {
	virtual {
		addrs = $VPN_SUBNET
		dns = $dns
	}
}

secrets {  # Do not create records with same id. It will be replaces previous secret
#	eap-user1 {
#		id = "fqdn:#{USERNAME_IN_HEX}"
#		secret = 0s{PASSWORD_IN_BASE64}
#	}
}
EOF

	# Setup renew hook for certbot service
	cat << EOF > "$CONF_DIR"/reload-certs.sh
#!/bin/sh

swanctl --flush-certs
swanctl --load-creds --clear
EOF

	# Service
	systemctl enable --now strongswan
}


case "$CONF_TYPE" in
	stroke ) stroke_conf; break ;;
	vici ) vici_conf; break ;;
	* ) echo "Unknown type '$CONF_TYPE'"; return ;;
esac

#
# Certbot service
#

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
