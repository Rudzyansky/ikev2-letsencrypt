# IKEv2 Setup Script

Script for automatic deployment of the IKEv2 server service.

The server side uses a certificate issued by Let's Encrypt.<br>
The client side connects without a certificate. Authentication is by username and password.

If you need a CA certificate (e.g. in the RouterOS), you can download it from the official website: [ISRG Root X1](https://letsencrypt.org/certs/isrgrootx1.pem) (root, required), [R3](https://letsencrypt.org/certs/lets-encrypt-r3.pem) (intermediate, optional).

## Launch

```bash
ssh vpn 'curl -s https://false.team/ikev2 | sudo bash -s vpn.example.com support@example.com user1 user2'
```

Where `vpn.example.com` is the FQDN (for connecting and cert), `support@example.com` is the e-mail for notifications from Let's Encrypt, `user1 user2` is the users set separated by a space.

# Client connection
## RouterOS

### CA certificate import
```routeros
/tool fetch url="https://letsencrypt.org/certs/isrgrootx1.pem"
/certificate import passphrase="" file-name=isrgrootx1.pem
```

### Peer setup
```routeros
/ip ipsec policy group add name=vpn
/ip ipsec mode-config add name=vpn responder=no connection-mark=tunnel

/ip ipsec profile add name=vpn hash-algorithm=sha384 enc-algorithm=aes-256 dh-group=ecp384
/ip ipsec proposal add name=vpn auth-algorithms=sha256 enc-algorithms=aes-256-cbc pfs-group=modp2048

/ip ipsec peer add name=vpn address="vpn.example.com" profile=vpn exchange-mode=ike2 
/ip ipsec identity add peer=vpn auth-method=eap eap-methods=eap-mschapv2 username="user1" password="p@ssw0rd" policy-template-group=vpn mode-config=vpn generate-policy=port-strict
```

### Change MSS
```routeros
/ip firewall mangle add action=change-mss chain=forward comment="IKE2: Clamp TCP MSS from LAN to ANY" ipsec-policy=in,ipsec new-mss=1360 passthrough=yes protocol=tcp tcp-flags=syn tcp-mss=!0-1360
/ip firewall mangle add action=change-mss chain=forward comment="IKE2: Clamp TCP MSS from ANY to LAN" ipsec-policy=out,ipsec new-mss=1360 passthrough=yes protocol=tcp tcp-flags=syn tcp-mss=!0-1360
```

### Creating rule for tunnel
```routeros
/ip firewall mangle add action=mark-connection chain=prerouting comment="Mark tunnel list to IPSec tunnel" dst-address-list=tunnel new-connection-mark=tunnel passthrough=yes
```

### Append address to list
```routeros
/ip firewall address-list add list=tunnel address=2ip.ru
```

## Windows

<details>
    <summary>PowerShell</summary>

```powershell
Add-VpnConnection -Name "My VPN" -ServerAddress "vpn.example.com" -TunnelType "Ikev2" -AuthenticationMethod "Eap" -RememberCredential

# https://github.com/paulstancer/VPNCredentialsHelper
Install-Module -Name VPNCredentialsHelper
Set-VpnConnectionUsernamePassword -ConnectionName "My VPN" -Username "user1" -Password "p@ssw0rd"

# https://docs.microsoft.com/powershell/module/vpnclient/set-vpnconnectionipsecconfiguration
Set-VpnConnectionIPsecConfiguration -ConnectionName "My VPN" -EncryptionMethod "AES256" -IntegrityCheckMethod "SHA384" -DHGroup "ECP384" -CipherTransformConstants "AES256" -AuthenticationTransformConstants "SHA256128" -PfsGroup "PFS2048" -Force
```
</details>

### Change MSS
```powershell
# If you've not connected before
New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\" -Name "$((Get-VpnConnection -Name "My VPN").Guid)"

# https://docs.microsoft.com/troubleshoot/windows-client/networking/tcpip-and-nbt-configuration-parameters
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$((Get-VpnConnection -Name "My VPN").Guid)" -Name "MTU" -PropertyType "DWord" -Value "1360" -Force
```

## Android
[strongSwan VPN Client](https://play.google.com/store/apps/details?id=org.strongswan.android) (Google Play)

## macOS / iOS
`Remote ID` is FQDN (e.g. vpn.example.com)<br>
`Local ID` leave empty
