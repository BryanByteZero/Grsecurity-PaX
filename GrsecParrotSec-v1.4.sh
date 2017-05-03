
## ================================================================================== ##
echo "Hi my name is xe1phix, and this is a tutorial for "
echo "manually compiling & hardening your kernel on parrot OS"
## ================================================================================== ##



#
# vmlinux
#   ^
#   |
#   +-< $(KBUILD_VMLINUX_INIT)
#   |   +--< init/version.o + more
#   |
#   +--< $(KBUILD_VMLINUX_MAIN)
#   |    +--< drivers/built-in.o mm/built-in.o + more
#   |
#   +-< ${kallsymso} (see description in KALLSYMS section)
#


Steps:


make mrproper
make menuconfig
make bzimage
make modules
make modules_install
make install



## =================================================================================== ##
## 	    /\													  /\
## ====/==\==================================================/==\===
##	 	||  ____                      _     ____              ||
## 		|| |  _ \ __ _ _ __ _ __ ___ | |_  / ___|  ___  ___   ||
## 		|| | |_) / _` | '__| '__/ _ \| __| \___ \ / _ \/ __|  ||
## 		|| |  __/ (_| | |  | | | (_) | |_   ___) |  __/ (__   ||
## 		|| |_|   \__,_|_|  |_|  \___/ \__| |____/ \___|\___|  ||
## 		|| ================================================== ||
##		||													  ||
##		\/													  \/
## =================================================================================== ##


##########################################################################################################################
## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ParrotSec Repository ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ## ##
##########################################################################################################################
##
## --------------------------------------------------------------------------------------------- ##
## wget -qO - http://archive.parrotsec.org/parrot/misc/parrotsec.gpg | apt-key add -
## wget -qO - http://archive.parrotsec.org/parrot/misc/parrotsec.gpg > parrotsec.gpg
## --------------------------------------------------------------------------------------------- ##
## openssl x509 -in /usr/local/share/ca-certificates/frozenCA.crt -noout -text
## --------------------------------------------------------------------------------------------- ##

gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xC686553B9795FA72214DE39CD7427F070F4FC7A6
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xD9AA2A5D8FC42717EED85EC126096AE9CBD7FB08
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xC07B79F43025772903D19385042FB0305F53BE86
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xB35050593C2F765640E6DDDB97CAA129F4C6B9A4

gpg --export B35050593C2F765640E6DDDB97CAA129F4C6B9A4 | sudo apt-key add -
gpg --export C07B79F43025772903D19385042FB0305F53BE86 | sudo apt-key add -
gpg --export D9AA2A5D8FC42717EED85EC126096AE9CBD7FB08 | sudo apt-key add -
gpg --export C686553B9795FA72214DE39CD7427F070F4FC7A6 | sudo apt-key add -



COMPILEDEPS="flex bison libncurses5-dev fakeroot gcc-6-plugin-dev libgmp-dev libmpfr-dev libmpc-dev libssl-dev build-essential gcc-${GCC_VERSION}-plugin-dev bc"

## ================================================================================== ##
echo "Download the prereq binaries:"
## ================================================================================== ##
apt-get update && apt-get install flex bison libncurses5-dev fakeroot gcc-6-plugin-dev libgmp-dev libmpfr-dev libmpc-dev libssl-dev build-essential


or


apt-get build-dep linux

apt-get source linux

## ================================================================================== ##
echo "make sure the parrot archive keyring is installed. it should be by default."
## ================================================================================== ##
apt-get update && apt-get install parrot-archive-keyring

wget -qO - http://archive.parrotsec.org/parrot/misc/parrotsec.gpg | apt-key add -


## ================================================================================== ##
echo "Is Curl Currently Installed?"
echo "If The Answer is no, install it."
## ================================================================================== ##
if [ -z `which curl` ]; then
	echo "==> Installing curl ..."
	apt-get -y -qq install curl &> /dev/null
	if [ $? -eq 0 ]; then echo "OK"; else echo "Failed"; exit 1; fi
fi


function scurl {
	curl --verbose --ssl-reqd --tlsv1.3 --progress-bar --proto=https $1
}


## ================================================================================== ##
echo "Grap the linux kernel over tls, output to /usr/src"
## ================================================================================== ##
curl --verbose --ssl-reqd --tlsv1.3 --progress-bar --url https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.9.13.tar.xz --output /usr/src/linux-4.9.13.tar.xz
curl --verbose --ssl-reqd --tlsv1.3 --progress-bar --url https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.9.13.tar.xz.sign --output /usr/src/linux-4.9.13.tar.xz.sign

echo "or"

## ================================================================================== ##
echo "Grab the linux kernel with wget"
## ================================================================================== ##
wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.9.13.tar.xz
wget https://cdn.kernel.org/pub/linux/kernel/v4.x/linux-4.9.13.tar.xz.sign


## ================================================================================== ##
echo "Generate a GPG key with 4096 bits"
## ================================================================================== ##
gpg2 --full-gen-key --enable-large-rsa

xe1phix
xe1phix@mail.i2p

What keysize do you want? (2048) 4096
Key is valid for? (0) 6m



## ================================================================================== ##
echo "Harden the gpg.conf file"
echo "Riseup.net's gpg.conf file is a good reference:"
## ================================================================================== ##
wget https://raw.githubusercontent.com/ioerror/duraconf/master/configs/gnupg/gpg.conf
echo gpg.conf > ~/.gnupg/gpg.conf


## ================================================================================== ##
echo "or use my Gnupg Configurations:"
## ================================================================================== ##
cat /home/faggot/RubbinStrangerz/Grsec+PaX/Gnupg2/gpg-TopKek.conf > /root/.gnupg/gpg.conf
cat /home/faggot/RubbinStrangerz/Grsec+PaX/Gnupg2/dirmngr-conf.skel > /root/.gnupg/dirmngr.conf




## ================================================================================== ##
echo "Fetch the needed GPG signing keys:"
echo "I prefer using the sks-keyservers.net keyserver because:"
echo "1). Lookups are performed using pgpkey-https by the sks-keyservers.net CA"
echo "2). The only port open on the sks-keyserver is port 443 (tls-ssl)" 
## ================================================================================== ##


## ================================================================================== ##
echo "Fetch the sks-keyserver GPG Signing Key:"
## ================================================================================== ##
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0x94CBAFDD30345109561835AA0B7F8B60E3EDFAE3



## ================================================================================== ##
echo "Now Sign the GPG Key:"
## ================================================================================== ##
gpg --lsign 0x94CBAFDD30345109561835AA0B7F8B60E3EDFAE3



## ================================================================================== ##
echo "Make the directory for the .pem in the Riseup.net config file:"
echo "Here an in-depth overview if you are new to the subject:"
echo "https://riseup.net/en/gpg-best-practices"
## ================================================================================== ##
curl --verbose https://sks-keyservers.net/ca/crl.pem --output /usr/local/etc/ssl/certs/hkps.pool.sks-keyservers.net.pem
curl --verbose https://sks-keyservers.net/sks-keyservers.netCA.pem.asc --output /usr/local/etc/ssl/certs/hkps.pool.sks-keyservers.net.pem.asc




## ================================================================================== ##
echo "cd into the directory you placed the signed .pem file:"
## ================================================================================== ##
cd /usr/local/etc/ssl/certs/




## ================================================================================== ##

## ================================================================================== ##
gpg --verify sks-keyservers.netCA.pem.asc









## ==================================================================================================== ##
echo "Receive Bradley Spengler (spender) Grsecurity GPG signing key:"
## ==================================================================================================== ##
gpg --keyserver hkps.pool.sks-keyservers.net --recv-keys 0x647F28654894E3BD457199BE38DBBDC86092693E

## gpg --export 647F28654894E3BD457199BE38DBBDC86092693E | sudo apt-key add -

## ==================================================================================================== ##
echo "Fetch the Grsec signing key:"
## ==================================================================================================== ##
gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 0xDE9452CE46F42094907F108B44D1C0F82525FE49

gpg ‐‐keyserver hkp://qdigse2yzvuglcix.onion ‐‐recv‐keys 0x38DBBDC86092693E
## ============================================================================================ ##
echo "You can use the tor .onion keyserver if you have it preconfigured to fetch over tor"
echo "This wont be covered in this Tutorial, but here is the sks-keyservers.net .onion address:"
## -------------------------------------------------------------------------------------------- ##
echo "hkp://jirk5u4osbsr34t5.onion"
## -------------------------------------------------------------------------------------------- ##
## ============================================================================================ ##


curl -o i2p-debian-repo-key.asc -3 --tlsv1.2 --verbose https://geti2p.net/_static/i2p-debian-repo.key.asc











http-proxy=socks4a://127.0.0.1:59050
curl --socks5 127.0.0.1:9150


echo "To Anonymize GPG Key Fetches With Tor's Socks5 Proxy Add This to Your gpg.conf File:"

keyserver-options http-proxy=socks5-hostname://127.0.0.1:9050

echo "To Anonymize GPG Key Fetches With I2P HTTP/S Proxy Add This to Your gpg.conf File:"
keyserver-options http-proxy=http-hostname://127.0.0.1:4444

## Send Your Public Keys To The hkp://cryptonomicon.mit.edu keyserver
gpg --keyserver hkp://18.9.60.141 --keyserver-options "$keyservopts" --send-keys $@
echo "To Fetch Files With Curl, such as:"
echo "## +~+~+~+~+~+~+~+~~+~+~+~+~~+~+~+~+~+ ##"
echo "1). GPG Keys From i2p eepsites"
echo "2). Keyrings From i2p eepsites"
echo "2). Binary Files From i2ps Most Distinguished" 
echo "	  Developer (KillYourTV). Operates His Own "
echo "    Debian Repo eepsite:"
echo "    killyourtv.i2p
echo "## +~+~+~+~+~+~+~+~~+~+~+~+~~+~+~+~+~+ ##"



## ---------------------------------------------------------------------------------- ##
echo "KillYourTV Also Utilizes The Dropbox Platform As A Binary" 
echo "Repository Which Encapsulates Apt-transport Through"  
echo "https To Add Another Layer of Authentication (TLS)"
## ---------------------------------------------------------------------------------- ##



## ========================================================================== ##
echo "Use I2P Proxy To Fetch KillYourTVs Pub GPG Key From His eepsite:"
## ========================================================================== ##
curl --resolve 127.0.0.1:4444:http://killyourtv.i2p/killyourtv.asc


## =================================================================================== ##
echo "Use curl To Fetch I2Ps Main Pub GPG Key From KYTVs Debian Dropbox Repository:"
## =================================================================================== ##
curl --tlsv1.2 --url https://dl.dropboxusercontent.com/u/18621288/debian/pool/main/i/i2p-keyring/i2p-keyring_2014.09.25_all.deb --output ~/Gnupg/i2p-keyring_2014.09.25_all.deb


## ========================================================================== ##
echo "KillYourTVs Dropbox Debian Repo URL is:"
## ========================================================================== ##
echo "deb https://dl.dropboxusercontent.com/u/18621288/debian/ wheezy main"


## ========================== ##
echo "The I2P Homepage is:"
## ========================== ##
http://127.0.0.1:7657/home






## ================================================================================== ##
echo "verify the Grsec fingerprints:"
## ================================================================================== ##
gpg --fingerprint 0x44D1C0F82525FE49
## ---------------------------------------------------------------------------------- ##
     		 DE94 52CE 46F4 2094 907F 108B 44D1 C0F8 2525 FE49
Fingerprint: DE94 52CE 46F4 2094 907F 108B 44D1 C0F8 2525 FE49
## ---------------------------------------------------------------------------------- ##



## ================================================================================== ##
echo "Verify Greg Kroah-Hartmans (Linux kernel stable release signing key):"
## ================================================================================== ##
gpg --fingerprint 0x38DBBDC86092693E
## ---------------------------------------------------------------------------------- ##
Primary key fingerprint: 647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E
						 647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E
## ---------------------------------------------------------------------------------- ##


#!/bin/sh

function fpr {
	gpg --fingerprint $i | grep fingerprint
}





## ================================================================================== ##
echo "Edit Greg Kroah-Hartmans (Linux kernel stable release signing key):"
## ================================================================================== ##
gpg --edit-key 0x38DBBDC86092693E
## ================================================================================== ##



## ================================================================================== ##
echo "Sign Greg Kroah-Hartmans (Linux kernel stable release signing key):"
## ================================================================================== ##
gpg> fpr
## ----------------------------------------------------------------------------------------------------------------------- ##
pub   rsa4096/38DBBDC86092693E 2011-09-23 Greg Kroah-Hartman (Linux kernel stable release signing key) <greg@kroah.com>
 Primary key fingerprint: 647F 2865 4894 E3BD 4571  99BE 38DB BDC8 6092 693E
## ----------------------------------------------------------------------------------------------------------------------- ##
gpg> lsign
gpg> save
## ================================================================================== ##



## ================================================================================== ##
echo "Edit Bradley Spengler (spender) Grsecurity GPG signing key:"
## ================================================================================== ##
gpg --edit-key 0x44D1C0F82525FE49




## ================================================================================== ##
echo "Check & Sign Bradley Spengler (spender) Grsecurity GPG signing key:"
## ================================================================================== ##
gpg> fpr
## ----------------------------------------------------------------------------------------------------------------------- ##
pub   rsa4096/44D1C0F82525FE49 2013-11-10 Bradley Spengler (spender) <spender@grsecurity.net>
 Primary key fingerprint: DE94 52CE 46F4 2094 907F  108B 44D1 C0F8 2525 FE49
## ----------------------------------------------------------------------------------------------------------------------- ##
gpg> lsign
gpg> save






## ================================================================================== ##
echo "or you could just use --lsign:"
## ================================================================================== ##

## ================================================================================== ##
echo "Locally Sign Greg Kroah-Hartmans (Linux kernel stable release signing key)"
## ================================================================================== ##
gpg --lsign 0x0x647F28654894E3BD457199BE38DBBDC86092693E

## ================================================================================== ##
echo "Locally Sign Bradley Spengler (spender) Grsecurity GPG signing key:"
## ================================================================================== ##
gpg --lsign 0x0xDE9452CE46F42094907F108B44D1C0F82525FE49


gpg --export  | sudo apt-key add -
gpg --keyserver pool.sks-keyservers.net --send-keys 0x


gpg --keyid-format long --import


## ================================================================================================= ##
## _________________________________________________________________________________________________ ##
# deb http://mirrors.kernel.org/debian/ stable main
# deb-src http://mirrors.kernel.org/debian/ stable main

# deb http://mirrors.kernel.org/debian/ unstable main
# deb-src http://mirrors.kernel.org/debian/ unstable main


## #############################################################################
## ========================================================================== ##
## #############################################################################
# deb http://www.grsecurity.net/debian/ stable main
# deb http://www.grsecurity.net/debian/ testing main
# deb http://www.grsecurity.net/debian/ unstable main







hardening-check --verbose --color --debug
hardening-check --report-functions

getent ahosts; getent  ahostsv4; getent  ahostsv6; getent  aliases; getent  ethers; getent  group; getent  gshadow; getent  hosts; getent  initgroups; getent  netgroup; getent  networks; getent  passwd; getent  protocols; getent  rpc; getent  services; getent shadow



## ================================================================================== ##
echo "Set User home directory environment variable:"
echo "open a user terminal, and type:"
## ================================================================================== ##
export HOME=/home/$USER


## ================================================================================== ##
echo "Make a grsec directory in the user directory"
## ================================================================================== ##
mkdir $HOME/Grsec; cd $HOME/Grsec

## ================================================================================== ##
echo "Fetch Spenders GPG Key with curl:"
## ================================================================================== ##
curl -O https://grsecurity.net/spender-gpg-key.asc

## ================================================================================== ##
echo "import Bradley Spengler (spender) Grsecurity GPG signing key:"
## ================================================================================== ##
gpg --keyid-format long --import spender-gpg-key.asc
 && gpg --fingerprint 2EEACCDA | grep fingerprint

## ================================================================================== ##
echo "Fetch the Grsecurity patches, Signatures, and Packages:"
## ================================================================================== ##


## ================================================================================== ##
echo "You can either use curl:"
## ================================================================================== ##
curl -O https://grsecurity.net/test/grsecurity-3.1-4.9.13-201702270729.patch
curl -O https://grsecurity.net/test/grsecurity-3.1-4.9.13-201702270729.patch.sig
curl -O https://grsecurity.net/stable/gradm-3.1-201701031918.tar.gz
curl -O https://grsecurity.net/stable/gradm-3.1-201701031918.tar.gz.sig
curl -O https://grsecurity.net/stable/grsecurity-2.2.0-iptables.patch
curl -O https://grsecurity.net/stable/grsecurity-2.2.0-iptables.patch.sig
curl -O https://grsecurity.net/paxctld/paxctld_1.2.1-1_amd64.deb
curl -O https://grsecurity.net/paxctld/paxctld_1.2.1-1_amd64.deb.sig

## ================================================================================== ##
echo "or you can use wget to fetch the patches, archives, binaries, and signatures:"
## ================================================================================== ##
## --------------------------------------------------------------------------- ##
echo "(You will be verifying their integrity with spenders GPG key anyways):"
## --------------------------------------------------------------------------- ##
wget https://grsecurity.net/test/grsecurity-3.1-4.9.13-201702270729.{patch,patch.sig}
wget https://grsecurity.net/stable/grsecurity-2.2.0-iptables.{patch,patch.sig}
wget https://grsecurity.net/stable/gradm-3.1-201701031918.{tar.gz,tar.gz.sig}
wget https://grsecurity.net/paxctld/paxctld_1.2.1-1_amd64.{deb,deb.sig}



https://grsecurity.net/~spender/paxtest-0.9.15.tar.gz
https://grsecurity.net/~spender/paxtest-0.9.15.tar.gz.sig




https://grsecurity.net/~spender/nvidia-drivers-352.09-pax.patch
https://grsecurity.net/~spender/grsec_logspoof.diff


https://grsecurity.net/~spender/random_mac.diff


"Add random offset to TCP timestamps"

https://grsecurity.net/~spender/random_timestamp.diff




https://grsecurity.net/~spender/new_net_fix.diff
https://grsecurity.net/~spender/grsec_ipc_harden.diff





## ================================================================================== ##
echo "Verify all of the grsec files you downloaded:"
## ================================================================================== ##
gpg --verify grsecurity-3.1-4.9.13-201702270729.patch.sig
gpg --verify grsecurity-2.2.0-iptables.{patch.sig,patch}
gpg --verify gradm-3.1-201701031918.tar.gz.sig
gpg --verify paxctld_1.2.1-1_amd64.{deb.sig,deb}


## ================================================================================== ##
echo "Open a root terminal, or type su into the existing terminal"
## ================================================================================== ##
su



## ================================================================================== ##
echo "Copy everything into /usr/src/ directory:"
## ================================================================================== ##
cp -v linux-4.9.13.tar /usr/src/
cp -v grsecurity-3.1-4.9.13-201702270729.patch /usr/src/
cp -v grsecurity-2.2.0-iptables.patch /usr/src/
cp -v gradm-3.1-201701031918.tar.gz /usr/src/



## ============================================================================================== ##
echo "Uncompressing the archive, using unxz & Verify the .tar archive against the signature:"
## ============================================================================================== ##
xz -cd linux-4.9.13.tar.xz | gpg2 --verify linux-4.9.13.tar.sign -

## ============================================================================================== ##
echo "Extract the kernel archive:"
## ============================================================================================== ##
tar -xf linux-4.9.13.tar

## ============================================================================================== ##
echo "cd into the kernel folder:"
## ============================================================================================== ##
cd linux-4.9.13




## ============================================================================================== ##
echo "Copy The Current Kernel Configurations"
## ============================================================================================== ##
cp /boot/config-* /usr/src/linux/.config



## ============================================================================================== ##
echo "Page Through The Current Source Config File"
## ============================================================================================== ##
cat /usr/src/.config | less



## ============================================================================================== ##
echo "To Search For Specific Kernel Parameters"
## ============================================================================================== ##
cat /usr/src/.config | grep




## ============================================================================================== ##
echo "Patch the Kernel with Grsecurity"
## ============================================================================================== ##
patch -p1 < ../grsecurity-3.1-4.9.13-201702270729.patch 






## ============================================================================================== ##
echo "Make sure you have all the PaX utilities installed:"
## ============================================================================================== ##
apt-get update && apt-get install paxrat paxtest pax-utils paxctl paxctld






make‐kpkg ‐‐initrd ‐‐append‐to‐version "grsec1.0" kernel_image

make menuconfig



echo "This part is gonna take awhile..."
echo 
fakeroot make ‐j 5 deb‐pkg





cd ..


dpkg -i linux‐image‐*‐grsec_*‐*_*.deb
dpkg -i linux‐firmware*.deb
dpkg -i linux‐headers*.deb
dpkg -i linux‐libc*.deb
dpkg -i paxctld*.deb




echo "Upgraded Kernel Builds"

make oldconfig



echo "prepare and compile:"
tar xzf gradm*.tar.gz

echo "cd into the directory:"
cd gradm

make


export KERNEL_DIR=/usr/src/
export IPTABLES_DIR=/path/to/iptables/source
./runme extra


cd /usr/src/linux
make dep bzImage modules modules_install
make install




apt-get update && apt-get install radare2-plugins lime-forensics-dkms libaff4-utils gpart gifshuffle forensics-full forensics-extra-gui forensics-extra exifprobe disktype ext3grep dff chaosreader wipe nautilius-wipe shred secure-delete strace 













echo "Add the iptables patch:"
patch ‐p1 < ../grsecurity‐*‐iptables.patch



echo "Compile and install:"
make install


## ============================================================================================== ##
echo "A list of grsec/PaX Configuration Definitions can be found here:"
## ============================================================================================== ##
## 
## ----------------------------------------------------------------------------------------------------------------------- ##
echo "https://en.wikibooks.org/wiki/Grsecurity/Appendix/Grsecurity_and_PaX_Configuration_Options"
## ----------------------------------------------------------------------------------------------------------------------- ##


cat /lib/modules/$(uname -r)/build/.config




Grab the kernel version string used in the GRUB bootloader menu:

grep menuentry /boot/grub/grub.cfg | cut -d "'" -f2 | grep "grsec$"


Set the new kernel to boot by default, and reboot:

sed -i "s/^GRUB_DEFAULT=.*$/GRUB_DEFAULT=\"Advanced options for Debian GNU\/Linux>Debian GNU\/Linux, with Linux 4.3.3-grsec\"/" /etc/default/grub
update-grub
grub-reboot "Advanced options for Debian GNU/Linux>Debian GNU/Linux, with Linux 4.3.3-grsec"
shutdown -r now





Set some PaX flags for GRUB:

paxctl -Cpm /usr/sbin/grub-probe
paxctl -Cpm /usr/sbin/grub-mkdevicemap
paxctl -Cpm /usr/sbin/grub-install
paxctl -Cpm /usr/bin/grub-script-check
paxctl -Cpm /usr/bin/grub-mount


paxctl -c /usr/bin/python2.7
paxctl -m /usr/bin/python2.7







gpg --homedir=~.gnupg --verify paxctld_1.2.1-1_amd64.{deb.sig,deb}
dpkg -i paxctld_1.2.1-1_amd64.deb
make install-deb
cp paxctld.conf /etc/paxctld.conf
paxctld -d
systemctl enable paxctld
mkdir /boot/grub
update-grub2

# update-grub
update-initramfs -k $KVER$KREV -c
update-initramfs -u

shutdown -h now

groupadd -g 9001 grsecproc
groupadd -g 9002 tpeuntrusted
groupadd -g 9003 denysockets







echo "specify which shared libraries they need within
echo "the dynamic information section:"

readelf -d /bin/bash | grep NEEDED


paxctl -c /usr/bin/vi
paxctl -v /usr/bin/vi



echo "Check Chrome headers:"
paxctl -v /opt/google/chrome/chrome
paxctl -v /opt/google/chrome/nacl_helper
paxctl -v /opt/google/chrome/chrome-sandbox 


To check if a library has executable stack enabled, run:

execstack -q /usr/lib/libcrypto.so.0.9.8



┌─[root@parrot]─[/home/xe1phix]
└──╼ #paxtest blackhat
PaXtest - Copyright(c) 2003-2014 by Peter Busser <peter@adamantix.org> and Brad Spengler <spender@grsecurity.net>
Released under the GNU Public Licence version 2 or later

Writing output to /root/paxtest.log
It may take a while for the tests to complete
Test results:
PaXtest - Copyright(c) 2003-2014 by Peter Busser <peter@adamantix.org> and Brad Spengler <spender@grsecurity.net>
Released under the GNU Public Licence version 2 or later

Mode: 1
Blackhat
Kernel: 
Linux parrot 4.8.17-grsec #1 SMP Tue Jan 17 21:53:04 MST 2017 x86_64 GNU/Linux

Relase information: 
Distributor ID:	Parrot
Description:	Parrot Security 3.4 - CyberFrigate
Release:	3.4
Codename:	cyberfrigate
Test results:
Executable anonymous mapping             : Killed
Executable bss                           : Killed
Executable data                          : Killed
Executable heap                          : Killed
Executable stack                         : Killed
Executable shared library bss            : Killed
Executable shared library data           : Killed
Executable anonymous mapping (mprotect)  : Killed
Executable bss (mprotect)                : Killed
Executable data (mprotect)               : Killed
Executable heap (mprotect)               : Killed
Executable stack (mprotect)              : Killed
Executable shared library bss (mprotect) : Killed
Executable shared library data (mprotect): Killed
Writable text segments                   : Killed
Anonymous mapping randomization test     : 28 quality bits (guessed)
Heap randomization test (ET_EXEC)        : 22 quality bits (guessed)
Heap randomization test (PIE)            : 35 quality bits (guessed)
Main executable randomization (ET_EXEC)  : 28 quality bits (guessed)
Main executable randomization (PIE)      : 28 quality bits (guessed)
Shared library randomization test        : 28 quality bits (guessed)
VDSO randomization test                  : 28 quality bits (guessed)
Stack randomization test (SEGMEXEC)      : 35 quality bits (guessed)
Stack randomization test (PAGEEXEC)      : 35 quality bits (guessed)
Arg/env randomization test (SEGMEXEC)    : 39 quality bits (guessed)
Arg/env randomization test (PAGEEXEC)    : 39 quality bits (guessed)
Randomization under memory exhaustion @~0: 28 bits (guessed)
Randomization under memory exhaustion @0 : 28 bits (guessed)
Return to function (strcpy)              : paxtest: return address contains a NULL byte.
Return to function (memcpy)              : Vulnerable
Return to function (strcpy, PIE)         : paxtest: return address contains a NULL byte.
Return to function (memcpy, PIE)         : Vulnerable




echo "perform administrative tasks while full system learning is enabled, authenticate to the admin role with:"

gradm -a admin

echo "To create a role-based learning log with gradm type:"
gradm -F -L /etc/grsec/learning.logs -O /etc/grsec/policy


enable learning, enable the system by executing:

# gradm -L /etc/grsec/learning.logs -E





echo "Systemd is a  debate between most linux admins for several reasons:"

echo "The Good attributes:"
echo "1). The previous init.d ecosystem was occasionally a rough patchwork"



echo "The bad Attributes:"
echo "1). Systemd is a truly behemoth of a set of programs."  
echo "2). With automation comes a relincwishing of administrative control. "
echo "	  And for a linux admin... Thats surely a way to piss off hackers."


echo "The ugly Attributes:"
echo "With large code, a need for attentive bug hunting "
echo "and patching seems like it would be self explanatory..."

echo "1). Apparently not for Redhat, they're too busy sucking microsofts dick to maintain the code."

echo "3). Which is a huuuge problem because systemd is now defaultly used "
echo "	  to construct almost all flavors of linux now..."


echo "soo... now we are dependant upon a very large.. BUGGY!! UNMAINTAINED! "
echo "Rudamentery fundation. This is why linus has publically shamed redhat over and over"
echo "Hopefully a new alternative will emerge and save us all."



echo "In the meantime... An experienced linux admin would be wise enough"
echo "To analyize hidden functions and processes."
echo "Know Your Enemy Well My Friends.."




systemd-analyze dump


Examining the initramfs contents


echo "unpack the contents of the initramfs into the current directory."

zcat /boot/initrd.img-3.2.0-2-686-pae | cpio -i



list the contents of an initramfs using the cpio -t option or the command

lsinitramfs /boot/initrd.img-*

dpkg-reconfigure linux-image-

echo "Lets take a look at the initrd image and its hidden systemd agenda:"

strings /sbin/init | grep -i systemd

/lib/modules/`uname -r`/vmlinux or /usr/lib/debug/lib64/modules/`uname -r`/vmlinux


readelf -h vmlinux











        /boot/System.map
        /System.map
        /usr/src/linux/System.map

    System.map also has versioning information, and klogd intelligently searches for the correct map file. For instance, suppose you're running kernel 2.4.18, and the associated map file is /boot/System.map. You now compile a new kernel 2.5.1 in the tree /usr/src/linux. During the compiling process, the file /usr/src/linux/System.map is created. When you boot your new kernel, klogd will first look at /boot/System.map, determine it's not the correct map file for the booting kernel, then look at /usr/src/linux/System.map, determine that it is the correct map file for the booting kernel and start reading the symbols.

    A few nota benes:

        Somewhere during the 2.5.x series, the Linux kernel started to untar into linux-version, rather than just linux (show of hands -- how many people have been waiting for this to happen?). I don't know if klogd has been modified to search in /usr/src/linux-version/System.map yet. TODO: Look at the klogd source. If someone beats me to it, please e-mail me and let me know if klogd has been modified to look in the new directory name for the linux source code.
        The manpage doesn't tell the whole the story. Look at this:
strace -f /sbin/klogd | grep 'System.map'
           31208 open("/boot/System.map-2.4.18", O_RDONLY|O_LARGEFILE) = 2
                        

        Apparently, not only does klogd look for the correct version of the map in the 3 klogd search directories, but klogd also knows to look for the name "System.map" followed by "-kernelversion", like System.map-2.4.18. This is undocumented feature of klogd.

    A few drivers will need System.map to resolve symbols (since they're linked against the kernel headers instead of, say, glibc). They will not work correctly without the System.map created for the particular kernel you're currently running. This is NOT the same thing as a module not loading because of a kernel version mismatch. That has to do with the kernel version, not the kernel symbol table which changes between kernels of the same version!

What else uses the System.map?

strace lsof 2>&1 1> /dev/null | grep System
readlink("/proc/22711/fd/4", "/boot/System.map-2.4.18", 4095) = 23


strace ps 2>&1 1> /dev/null | grep System
open("/boot/System.map-2.4.18", O_RDONLY|O_NONBLOCK|O_NOCTTY) = 6
            












## ================================================================================== ##
echo "References:"
## ================================================================================== ##



## ================================================================================== ##
echo "This process is really well documented here:"
echo "This guide is for VM's but most of it applies to host machines, as I will demonstrate:"
## ================================================================================== ##
## -------------------------------------------------------------------------------------------- ##
echo "https://www.whonix.org/wiki/Grsecurity"
## -------------------------------------------------------------------------------------------- ##



## ================================================================================== ##
echo "Another great guide is insanitybits:"
## ================================================================================== ##
## -------------------------------------------------------------------------------------------- ##
echo "http://www.insanitybit.com/2012/05/31/compile-and-patch-your-own-secure-linux-kernel-with-pax-and-grsecurity/"
## -------------------------------------------------------------------------------------------- ##


## ----------------------------------------------------------------------------------------------------------------------- ##


https://sks-keyservers.net/overview-of-pools.php
https://sks-keyservers.net/sks-keyservers.netCA.pem
https://sks-keyservers.net/sks-keyservers.netCA.pem.asc
https://sks-keyservers.net/ca/crl.pem
http://pool.sks-keyservers.net:11371/pks/lookup?op=vindex&search=0x94CBAFDD30345109561835AA0B7F8B60E3EDFAE3
hkp://jirk5u4osbsr34t5.onion 
https://kernel.org/category/signatures.html
https://grsecurity.net/download.php
https://grsecurity.net/~spender/?C=M;O=D

https://en.wikibooks.org/wiki/Grsecurity/Configuring_and_Installing_grsecurity
https://en.wikibooks.org/wiki/Grsecurity/Additional_Utilities
https://en.wikibooks.org/wiki/Grsecurity/The_RBAC_System
## ----------------------------------------------------------------------------------------------------------------------- ##



