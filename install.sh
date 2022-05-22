#/bin/bash

DEBUG_STD="&>/dev/null"
DEBUG_ERROR="2>/dev/null"
SUDO="sudo"

bred='\033[1;31m'
bblue='\033[1;34m'
bgreen='\033[1;32m'
byellow='\033[1;33m'
red='\033[0;31m'
blue='\033[0;34m'
green='\033[0;32m'
yellow='\033[0;33m'
reset='\033[0m'

# Installing latest Golang version
version=$(curl -L -s https://golang.org/VERSION?m=text)
#version="go1.17.6"
printf "${bblue} Running: Installing/Updating Golang ${reset}\n\n"
if [[ $(eval type go $DEBUG_ERROR | grep -o 'go is') == "go is" ]] && [ "$version" = $(go version | cut -d " " -f3) ]
    then
        printf "${bgreen} Golang is already installed and updated ${reset}\n\n"
    else
        eval $SUDO rm -rf /usr/local/go $DEBUG_STD
        if [ "True" = "$IS_ARM" ]; then
            if [ "True" = "$RPI_3" ]; then
                eval wget https://dl.google.com/go/${version}.linux-armv6l.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf ${version}.linux-armv6l.tar.gz $DEBUG_STD
            elif [ "True" = "$RPI_4" ]; then
                eval wget https://dl.google.com/go/${version}.linux-arm64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf ${version}.linux-arm64.tar.gz $DEBUG_STD
            fi
        elif [ "True" = "$IS_MAC" ]; then
            if [ "True" = "$IS_ARM" ]; then
                eval wget https://dl.google.com/go/${version}.darwin-arm64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf ${version}.darwin-arm64.tar.gz $DEBUG_STD
            else
                eval wget https://dl.google.com/go/${version}.darwin-amd64.tar.gz $DEBUG_STD
                eval $SUDO tar -C /usr/local -xzf ${version}.darwin-amd64.tar.gz $DEBUG_STD
            fi
        else
            eval wget https://dl.google.com/go/${version}.linux-amd64.tar.gz $DEBUG_STD
            eval $SUDO tar -C /usr/local -xzf ${version}.linux-amd64.tar.gz $DEBUG_STD
        fi
        eval $SUDO ln -sf /usr/local/go/bin/go /usr/local/bin/
        rm -rf $version*
        export GOROOT=/usr/local/go
        export GOPATH=$HOME/go
        export PATH=$GOPATH/bin:$GOROOT/bin:$HOME/.local/bin:$PATH
cat << EOF >> ~/${profile_shell}
# Golang vars
export GOROOT=/usr/local/go
export GOPATH=\$HOME/go
export PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.local/bin:\$PATH
EOF

fi

[ -n "$GOPATH" ] || { printf "${bred} GOPATH env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }
[ -n "$GOROOT" ] || { printf "${bred} GOROOT env var not detected, add Golang env vars to your \$HOME/.bashrc or \$HOME/.zshrc:\n\n export GOROOT=/usr/local/go\n export GOPATH=\$HOME/go\n export PATH=\$GOPATH/bin:\$GOROOT/bin:\$PATH\n\n"; exit 1; }

sudo apt install python3 python3-pip build-essential gcc cmake ruby git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx tor medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl -y

sudo apt-get install jq

wget https://github.com/findomain/findomain/releases/latest/download/findomain-linux
mv findomain-linux findomain
chmod +x findomain
mv findomain /usr/local/bin

git clone https://github.com/UnaPibaGeek/ctfr.git
cd ctfr
pip3 install -r requirements.txt
cd ../

git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt
cd ../

git clone https://github.com/devanshbatham/ParamSpider.git
cd ParamSpider
pip3 install -r requirements.txt
cd ../

go install github.com/Emoe/kxss@latest

go install github.com/hahwul/dalfox/v2@latest

go install github.com/ffuf/ffuf@latest

pip3 install s3scanner

git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
sudo pip install -r requirements.txt
cd ../

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

go install github.com/tomnomnom/assetfinder@latest

go install -v github.com/OWASP/Amass/v3/...@master

go install github.com/gwen001/github-subdomains@latest

go install github.com/gwen001/github-endpoints@latest

go install github.com/haccer/subjack@latest

go install github.com/Ice3man543/SubOver@latest

go install github.com/lc/gau/v2/cmd/gau@latest

GO111MODULE=on go install -v github.com/lc/subjs@latest

go install github.com/cgboal/sonarsearch/cmd/crobat@latest

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

go install github.com/tomnomnom/waybackurls@latest

go install github.com/tomnomnom/gf@latest

go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

go install -v github.com/tomnomnom/anew@latest

go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

git clone https://github.com/projectdiscovery/nuclei-templates.git

mv ~/go/bin/* /usr/local/bin

mkdir ~/Tools

mv nuclei-templates Sublist3r ParamSpider cloud_enum ctfr ~/Tools

wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb

dpkg -i rustscan_2.0.1_amd64.deb


