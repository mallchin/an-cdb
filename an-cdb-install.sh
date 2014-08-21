#!/bin/bash
# AN!Cluster Dashboard Installer v1.1.4

################################################################################
# TODO
#  - Make this less stupid.
#  - Sign our repo and RPMs.
#  - Remove 'apache' user SSH stuff once the new SSH system is better tested.
#  - Get selinux working
#  - Enable iptables support
#  - Make SSL default
################################################################################

########################################
# Config
########################################
#VERSION="1.1.4"
#INSTALL_ARCHIVE="v${VERSION}.tar.gz"
#INSTALL_EXTRACTED="an-cdb-${VERSION}"
ADMIN_USER="alteeve"
AN_FILES_URL="https://alteeve.ca/files/"
AN_REPO_URL="https://alteeve.ca/repo/el6/an.repo"
#AN_GIT_ARCHIVE="https://github.com/digimer/an-cdb/archive/"
AN_REPO_LOCAL="/etc/yum.repos.d/an.repo"
RELEASE_FILE="/etc/redhat-release"
RELEASE_MIN="*6.*"
#TMP_DIR="/root/tmp"

########################################
# Input defaults
########################################
PASSWORD="secret"
HOSTNAME=$(hostname)
CUSTOMER="Alteeve's Niche!"

########################################
# Test if is required release
########################################
if [ ! -f $RELEASE_FILE ]; then
	echo "This does not appear to be a RedHat (or derivative) release."
	echo "Please refer to the README for supported distributions."
	exit 1
fi

########################################
# Test if is required release version
########################################
if [[ `cat $RELEASE_FILE` != $RELEASE_MIN ]]; then
	echo "This does not appear to be a 6.x release."
	echo "Please refer to the README for supported versions."
	exit 1
fi

########################################
# Header
########################################
clear;
echo "##############################################################################"
echo "#   ___ _       _ _                                                          #"
echo "#  / __| |_ _ _(_) |_____ _ _                                                #"
echo "#  \__ \  _| '_| | / / -_) '_|                                               #"
echo "#  |___/\__|_| |_|_\_\___|_|                                                 #"
echo "#                                                                            #"
echo "# AN!Cluster Dashboard Installer                                             #"
echo "#                                                                            #"
echo "##############################################################################"

########################################
# Inputs
########################################
echo ""
echo "Enter the dashboard's hostname:"
echo -n "[$HOSTNAME] "
read NEWHOSTNAME
if [ "$NEWHOSTNAME" != "" ]; then
	HOSTNAME=$NEWHOSTNAME
fi
echo ""
echo "Enter a password for the admin user:"
echo -n "[] "
read -s PASSWORD
echo ""
echo "Enter your entity (person/company/organization) description:"
echo -n "[] "
read CUSTOMER
echo ""
echo "Using the following values:"
echo " - Host name: [$HOSTNAME]"
echo " - Customer:  [$CUSTOMER]"
echo " - Password:  <HIDDEN>"

########################################
# Proceed with install?
########################################
echo ""
read -r -p "Proceed with install? [y/N] " response
response=${response,,}
if [[ ! $response =~ ^(yes|y)$ ]]; then
	exit 1
fi

########################################
# Add AN!Repo
########################################
echo -e "\e[1;32m >>> Adding AN!Repo...\e[0m"
if [ ! -f $AN_REPO_LOCAL ]; then
	curl $AN_REPO_URL > $AN_REPO_LOCAL
	if [ ! -f $AN_REPO_LOCAL ]; then
		echo -e "\e[1;32mERROR: Failed to write: [$AN_REPO_LOCAL]\e[0m"
		exit 1
	fi
fi

########################################
# Clean yum
########################################
echo -e "\e[1;32m >>> Cleaning yum...\e[0m"
yum clean all

########################################
# Update
########################################
echo -e "\e[1;32m >>> Updating system...\e[0m"
yum -y update

########################################
# Installing required packages
########################################
echo -e "\e[1;32m >>> Installing required packages...\e[0m"

# Base
yum -y install cpan perl-YAML-Tiny perl-Net-SSLeay perl-CGI fence-agents \
               syslinux openssl-devel httpd screen ccs vim mlocate wget man \
               perl-Test-Simple policycoreutils-python mod_ssl libcdio \
               perl-TermReadKey expect rsync

# X11
yum -y groupinstall basic-desktop x11 fonts
yum -y install firefox virt-manager qemu-kvm libvirt gedit

# Stuff from our repo
yum -y install perl-Net-SSH2

########################################
# Null qemu network defaults
########################################
#echo "\e[1;32m >>> Nulling qemu network defaults...\e[0m"
#cat /dev/null > /etc/libvirt/qemu/networks/default.xml

########################################
# Create /var/www/home
########################################
echo -e "\e[1;32m >>> Creating apache directories...\e[0m"
if [ ! -e "/var/www/home/archive" ]; then
	mkdir -p /var/www/home/archive
fi
if [ ! -e "/var/www/home/cache" ]; then
	mkdir -p /var/www/home/cache
fi
if [ ! -e "/var/www/home/media" ]; then
	mkdir -p /var/www/home/media
fi
if [ ! -e "/var/www/home/status" ]; then
	mkdir -p /var/www/home/status
fi
chown -R apache:apache /var/www/home

########################################
# Configure selinux
########################################
echo -e "\e[1;32m >>> Configuring SELinux...\e[0m"
if [ ! -e "/etc/selinux/config.anvil" ]; then
	sed -i.anvil 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
fi
if [ -e "/etc/sysconfig/network.anvil" ]; then
	sed -i "s/HOSTNAME=.*/HOSTNAME=$HOSTNAME/" /etc/sysconfig/network
else
	sed -i.anvil "s/HOSTNAME=.*/HOSTNAME=$HOSTNAME/" /etc/sysconfig/network
fi
if [ ! -e "/etc/passwd.anvil" ]; then
	sed -i.anvil 's/apache\(.*\)www:\/sbin\/nologin/apache\1www\/home:\/bin\/bash/g' /etc/passwd
fi
# If there is already a backup, just edit the customer's name
if [ -e "/etc/httpd/conf/httpd.conf.anvil" ]; then
	sed -i.anvil 's/Cluster Dashboard - .*/Striker Dashboard - $CUSTOMER/' /etc/httpd/conf/httpd.conf
else
	cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.anvil
	sed -i 's/Timeout 60/Timeout 60000/' /etc/httpd/conf/httpd.conf
	sed -i "/Directory \"\/var\/www\/cgi-bin\"/ a\    # Password login\n    AuthType Basic\n    AuthName \"Striker - $CUSTOMER\"\n    AuthUserFile /var/www/home/htpasswd\n    Require user admin" /etc/httpd/conf/httpd.conf
fi

########################################
# Configure ssh
########################################
echo -e "\e[1;32m >>> Configuring SSH...\e[0m"
if [ ! -e "/etc/ssh/sshd_config.anvil" ]; then
	# This prevents long delays logging in when the net is down.
	sed -i.anvil 's/#GSSAPIAuthentication no/GSSAPIAuthentication no/'   /etc/ssh/sshd_config
	sed -i       's/GSSAPIAuthentication yes/#GSSAPIAuthentication yes/' /etc/ssh/sshd_config
	sed -i       's/#UseDNS yes/UseDNS no/'                              /etc/ssh/sshd_config
   	/etc/init.d/sshd restart
fi

########################################
# Set hostname
########################################
echo -e "\e[1;32m >>> Setting hostname...\e[0m"
hostname $HOSTNAME

########################################
# Configure services
########################################
echo -e "\e[1;32m >>> Configuring services...\e[0m"
chkconfig iptables off
chkconfig ip6tables off
chkconfig firstboot off
chkconfig iptables on
chkconfig httpd on
#chkconfig acpid on
setenforce 0
#/etc/init.d/iptables stop
/etc/init.d/ip6tables stop
/etc/init.d/httpd start
#/etc/init.d/acpid start

########################################
# Generate key pairs
########################################
echo -e "\e[1;32m >>> Generate key pairs...\e[0m"
if [ ! -e "/root/.ssh/id_rsa" ]; then
	ssh-keygen -t rsa -N "" -b 8191 -f ~/.ssh/id_rsa
fi
if [ ! -e "/var/www/home/.ssh/id_rsa" ]; then
	su apache -c "ssh-keygen -t rsa -N \"\" -b 8191 -f ~/.ssh/id_rsa"
fi

########################################
# Configure /etc/an
########################################
echo -e "\e[1;32m >>> Configuring an...\e[0m"
if [ ! -e "/etc/an" ]; then
	mkdir /etc/an
fi
if [ ! -e "/var/log/an-cdb.log" ]; then
	touch /var/log/an-cdb.log
fi
if [ ! -e "/var/log/an-mc.log" ]; then
	touch /var/log/an-mc.log
fi

########################################
# Configure htpasswd
########################################
echo -e "\e[1;32m >>> Configuring htpasswd...\e[0m"
# Remove the old file and recreate it in case the use changed the password.
if [ -e /var/www/home/htpasswd ]; then
	rm -f /var/www/home/htpasswd
fi
su apache -c "htpasswd -cdb /var/www/home/htpasswd admin '$PASSWORD'"

########################################
# Install guacamole
########################################
echo -e "\e[1;32m >>> Installing guacamole...\e[0m"
if [ ! -e "/etc/guacamole/noauth-config.xml" ]; then

	# Install
	yum -y install tomcat6 guacd libguac-client-vnc libguac-client-ssh libguac-client-rdp
	
	# Test packages installed correctly
	OK=1
	if [ ! -e "/var/lib/tomcat6" ]; then
		OK=0        
	fi
	if [ ! -e "/etc/rc.d/init.d/guacd" ]; then
		OK=0        
	fi
	if [ ! -e "/usr/lib64/libguac-client-vnc.so" ]; then
		OK=0        
	fi
	if [ ! -e "/usr/lib64/libguac-client-ssh.so" ]; then
		OK=0        
	fi
	if [ ! -e "/usr/lib64/libguac-client-rdp.so" ]; then
		OK=0        
	fi
	if [ $OK != 1 ]; then
		echo -e "\e[1;32mERROR: Guacamole failed to install.\e[0m"
		exit 1
	fi

	# Configure
	if [ ! -e "/etc/guacamole" ]; then
		mkdir /etc/guacamole
		if [ ! -e "/etc/guacamole" ]; then
			echo -e "\e[1;32mERROR: Failed to create: [/etc/guacamole].\e[0m"
			exit 1
		fi
	fi
	if [ ! -e "/usr/share/tomcat6/.guacamole" ]; then
		mkdir -p /usr/share/tomcat6/.guacamole
		if [ ! -e "/usr/share/tomcat6/.guacamole" ]; then
			echo -e "\e[1;32mERROR: Failed to create: [/usr/share/tomcat6/.guacamole/].\e[0m"
			exit 1
		fi
	fi
	if [ ! -e "/var/lib/guacamole/classpath" ]; then
		mkdir -p /var/lib/guacamole/classpath
		if [ ! -e "/var/lib/guacamole/classpath" ]; then
			echo -e "\e[1;32mERROR: Failed to create: [/var/lib/guacamole/classpath].\e[0m"
			exit 1
		fi
	fi
	GUAC_AUTH="guacamole-auth-noauth-0.9.2.jar"
	if [ ! -e "/var/lib/guacamole/classpath/${GUAC_AUTH}" ]; then
		cp install/${GUAC_AUTH} /var/lib/guacamole/classpath/${GUAC_AUTH}
		if [ ! -e "/var/lib/guacamole/classpath/${GUAC_AUTH}" ]; then
			echo -e "\e[1;32mERROR: Failed to save: [/var/lib/guacamole/classpath/${GUAC_AUTH}].\e[0m"
			exit 1
		fi
	fi
	if [ ! -e "/var/lib/guacamole/guacamole.war" ]; then
		if [ -e "/tmp/sf.html" ]; then
			rm -f /tmp/sf.html
		fi
		wget http://sourceforge.net/projects/guacamole/files/current/binary -O /tmp/sf.html
		if [ -e "/tmp/sf.html" ]; then
			WAR=$(cat /tmp/sf.html |grep guacamole | grep "war/down" | sed 's/.*\(guacamole-0\..*\.war\)\/.*/\1/' | tr '\n' ' ' | awk '{print $1}')
			URL="http://sourceforge.net/projects/guacamole/files/current/binary/$WAR"
			wget -c $URL -O /var/lib/guacamole/$WAR
		else
			echo -e "\e[1;32mERROR: Failed to download guacamole WAR file.\e[0m"
			exit 1
		fi
		if ls /var/lib/guacamole/guacamole-* &>/dev/null
		then
			mv /var/lib/guacamole/$WAR /var/lib/guacamole/guacamole.war
			if [ ! -e "/var/lib/guacamole/guacamole.war" ]; then
				echo -e "\e[1;32mERROR: Failed to move $WAR to 'guacamole.war'\e[0m"
				exit 1
			fi
		fi
	fi
	if [ ! -e "/etc/guacamole/guacamole.properties" ]; then
		cp install/guacamole.properties /etc/guacamole/guacamole.properties
		if [ ! -e "/etc/guacamole/guacamole.properties" ]; then
			echo -e "\e[1;32mERROR: Failed to write: [/etc/guacamole/guacamole.properties].\e[0m"
			exit 1
		fi
	fi

	# Create symlinks
	if [ ! -e "/var/lib/tomcat6/webapps/guacamole.war" ]; then
		ln -s /var/lib/guacamole/guacamole.war /var/lib/tomcat6/webapps/
		if [ ! -e "/var/lib/tomcat6/webapps/guacamole.war" ]; then
			echo -e "\e[1;32mERROR: Failed to symlink guacamole.war.\e[0m"
			exit 1
		fi
	fi
	if [ ! -e "/usr/share/tomcat6/.guacamole/guacamole.properties" ]; then
		ln -s /etc/guacamole/guacamole.properties /usr/share/tomcat6/.guacamole/
		if [ ! -e "/usr/share/tomcat6/.guacamole/guacamole.properties" ]; then
			echo -e "\e[1;32mERROR: Failed to suymlink guacamole.properties.\e[0m"
			exit 1
		fi
	fi

	# Create the skeleton 'noauth-config.xml' file.
	if [ ! -e "/etc/guacamole/noauth-config.xml" ]; then
		cp install/noauth-config.xml /etc/guacamole/noauth-config.xml
		# This is needed to allow AN!CDB to create backups and modify the config
		chmod 777 /etc/guacamole
		chmod 666 /etc/guacamole/noauth-config.xml
		if [ ! -e "/etc/guacamole/noauth-config.xml" ]; then
			echo -e "\e[1;32mERROR: Failed to write guacamole configuration file.\e[0m"
			exit 1
		fi
	fi

	# Configure services
	chkconfig tomcat6 on
	chkconfig guacd on
	/etc/init.d/tomcat6 restart
	/etc/init.d/guacd restart

fi

########################################
# Install Striker core
########################################
echo -e "\e[1;32m >>> Installing Striker core...\e[0m"
#mkdir -p ${TMP_DIR}
#if [ ! -e "${TMP_DIR}/${INSTALL_ARCHIVE}" ]; then
#	wget -c ${AN_GIT_ARCHIVE}${INSTALL_ARCHIVE} -O ${TMP_DIR}/${INSTALL_ARCHIVE}
#	tar -xvzf ${TMP_DIR}/${INSTALL_ARCHIVE} -C ${TMP_DIR}
#	rsync -av ${TMP_DIR}/${INSTALL_EXTRACTED}/html /var/www/
#	rsync -av ${TMP_DIR}/${INSTALL_EXTRACTED}/cgi-bin /var/www/
#	rsync -av ${TMP_DIR}/${INSTALL_EXTRACTED}/tools /var/www/
#	rsync -av ${TMP_DIR}/${INSTALL_EXTRACTED}/an.conf /etc/an/
#fi
rsync -av html /var/www/
rsync -av cgi-bin /var/www/
rsync -av tools /var/www/
if [ ! -e "/etc/an/an.conf" ]; then
	cp install/an.conf /etc/an/.
fi

########################################
# Configure iptables
########################################
echo -e "\e[1;32m >>> Configure iptables...\e[0m"
iptables -I INPUT -m state --state NEW -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -p tcp --dport 443 -j ACCEPT
#iptables -I INPUT -m state --state NEW -p tcp --dport 8080 -j ACCEPT
/etc/init.d/iptables save

########################################
# Configure admin user
########################################
echo -e "\e[1;32m >>> Configuring admin user...\e[0m"
if [ ! -e "/home/${ADMIN_USER}" ]; then
	# Add user
	useradd ${ADMIN_USER}
	# Create desktop
	su ${ADMIN_USER} -c "mkdir /home/${ADMIN_USER}/Desktop"
	su ${ADMIN_USER} -c "cp /usr/share/applications/firefox.desktop /home/${ADMIN_USER}/Desktop/"
	chmod +x /home/${ADMIN_USER}/Desktop/firefox.desktop
	su ${ADMIN_USER} -c "cp /usr/share/applications/virt-manager.desktop /home/${ADMIN_USER}/Desktop/"
	chmod +x /home/${ADMIN_USER}/Desktop/virt-manager.desktop
	# Disable virt-manager's autoconnect to localhost
	mkdir -p /home/${ADMIN_USER}/.gconf/apps/virt-manager/connections
	cp install/%gconf.xml /home/${ADMIN_USER}/.gconf/apps/virt-manager/connections/%gconf.xml
	chown -R ${ADMIN_USER}:${ADMIN_USER} /home/${ADMIN_USER}/.gconf
	chmod go-rwx -R /home/${ADMIN_USER}/.gconf
	# Generate key pairs
	su ${ADMIN_USER} -c "ssh-keygen -t rsa -N \"\" -b 4095 -f ~/.ssh/id_rsa"
fi
echo $PASSWORD | passwd --stdin ${ADMIN_USER}

# Public keys file
echo "# Keys for the $HOSTNAME dashboard" > /home/${ADMIN_USER}/Desktop/public_keys.txt
cat /root/.ssh/id_rsa.pub /home/${ADMIN_USER}/.ssh/id_rsa.pub /var/www/home/.ssh/id_rsa.pub >> /home/${ADMIN_USER}/Desktop/public_keys.txt
echo "" >> /home/${ADMIN_USER}/Desktop/public_keys.txt
chown ${ADMIN_USER}:${ADMIN_USER} /home/alteeve/Desktop/public_keys.txt

########################################
# Set default runlevel
########################################
echo -e "\e[1;32m >>> Setting default runlevel...\e[0m"
sed -i 's/id:3:initdefault:/id:5:initdefault:/g' /etc/inittab

########################################
# Configure ownership and permissions
########################################
echo -e "\e[1;32m >>> Configure ownership and permissions...\e[0m"
chown -R apache:apache /var/www/*
chown apache:apache /var/log/an-cdb.log
chown apache:apache /var/log/an-*
chown root:apache -R /etc
chown root:apache -R /etc/an
chown root:apache -R /etc/ssh/ssh_config
chown root:apache -R /etc/hosts
chown root:root /var/www/tools/restart_tomcat6
chown root:root /var/www/tools/check_dvd
chown root:root /var/www/tools/do_dd
chown root:root /var/www/tools/call_gather-system-info
chmod 6755 /var/www/tools/check_dvd
chmod 6755 /var/www/tools/do_dd
chmod 6755 /var/www/tools/restart_tomcat6
chmod 6755 /var/www/tools/call_gather-system-info
chmod 770 /etc/an
chmod 660 /etc/an/*
chmod 664 /etc/ssh/ssh_config
chmod 664 /etc/hosts

########################################
# Footer
########################################
echo ""
echo "##############################################################################"
echo "#                                                                            #"
echo "#                       Dashboard install is complete.                       #"
echo "#                                                                            #"
echo "# When you reboot and log in, you should see a file called:                  #"
echo "# [public_keys.txt] on the desktop. Copy the contents of that file and add   #"
echo "# them to: [/root/.ssh/authorized_keys] on each cluster node you wish this   #"
echo "# dashboard to access.                                                       #"
echo "#                                                                            #"
echo "# Once the keys are added, switch to the: [apache] user and use ssh to       #"
echo "# connect to each node for the first time. This is needed to add the node's  #"
echo "# SSH fingerprint to the apache user's: [~/.ssh/known_hosts] file. You only  #"
echo "# need to do this once per node.                                             #"
echo "#                                                                            #"
echo "# Please reboot to ensure the latest kernel is being used.                   #"
echo "#                                                                            #"
echo "# Remember to update: [/etc/an/an.conf] and then copy it to each node!       #"
echo "#                                                                            #"
echo "##############################################################################"
echo ""

# Instructions for adding signed certs:
# [root@an-cdb conf.d]# diff -U0 ssl.conf.original ssl.conf
# --- ssl.conf.original        2014-04-18 15:38:15.229000449 -0400
# +++ ssl.conf        2014-04-18 15:39:30.663000165 -0400
# @@ -105 +105 @@
# -SSLCertificateFile /etc/pki/tls/certs/localhost.crt
# +SSLCertificateFile /etc/pki/CA/wildcard_ssl_alteeve.ca.crt
# @@ -112 +112 @@
# -SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
# +SSLCertificateKeyFile /etc/pki/CA/private/wildcard_alteeve.ca.key
# @@ -127,0 +128 @@
# +SSLCACertificateFile /etc/pki/CA/RapidSSL_CA_bundle.pem

### Configuring mod_proxy to front guacamole
### http://guac-dev.org/doc/gug/installing-guacamole.html#mod-proxy

### This enables UTF-8, not strictly needed.
# diff -U0 /etc/tomcat6/server.xml.anvil /etc/tomcat6/server.xml
# --- /etc/tomcat6/server.xml.anvil	2014-08-17 12:00:33.942041900 -0400
# +++ /etc/tomcat6/server.xml	2014-08-17 12:10:04.312040613 -0400
# @@ -70 +70,2 @@
# -               connectionTimeout="20000" 
# +               connectionTimeout="20000"
# +               URIEncoding="UTF-8" 
#
# /etc/init.d/tomcat6 restart
# Stopping tomcat6:                                          [  OK  ]
# Starting tomcat6:                                          [  OK  ]

# diff -U0 /etc/httpd/conf/httpd.conf.anvil /etc/httpd/conf/httpd.conf
# --- /etc/httpd/conf/httpd.conf.anvil	2014-08-17 12:04:55.697039671 -0400
# +++ /etc/httpd/conf/httpd.conf	2014-08-17 12:38:40.145039535 -0400
# @@ -956,0 +957,8 @@
# +<Location /guacamole/>
# +    Order allow,deny
# +    Allow from all
# +    ProxyPass http://localhost:8080/guacamole/ max=20 flushpackets=on
# +    ProxyPassReverse http://localhost:8080/guacamole/
# +</Location>
# +SetEnvIf Request_URI "^/guacamole/tunnel" dontlog
# +CustomLog  /var/log/httpd/guac.log common env=!dontlog
#
# /etc/init.d/httpd restart
# Stopping httpd:                                            [  OK  ]
# Starting httpd: httpd: apr_sockaddr_info_get() failed for an-m03.alteeve.ca
# httpd: Could not reliably determine the server's fully qualified domain name, using 127.0.0.1 for ServerName
#                                                            [  OK  ]
