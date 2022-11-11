#!/usr/bin/env bash

RED="\e[31m"
GREEN="32"
BOLDGREEN="\e[1;${GREEN}m"
ENDCOLOR="\e[0m"

clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                     Installing The Requirements Tools                 #"
echo "   #########################################################################"

echo ""
echo ""
echo ""

echo "   #########################################################################"
echo "   #                            Installing Golang                          #"
echo "   #########################################################################"


echo -e "${RED}"

wget https://go.dev/dl/go1.18.1.linux-amd64.tar.gz

rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.1.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin

rm -rf go1.18.1.linux-amd64.tar.gz
clear



echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                         Installing Main-tools                         #"
echo "   #########################################################################"

echo -e "${RED}"

sudo apt install python3 python3-pip build-essential gcc cmake ruby git curl libpcap-dev wget zip python3-dev pv dnsutils libssl-dev libffi-dev libxml2-dev libxslt1-dev zlib1g-dev nmap jq apt-transport-https lynx tor medusa xvfb libxml2-utils procps bsdmainutils libdata-hexdump-perl -y

sudo apt-get install jq
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing AWS-CLI                          #"
echo "   #########################################################################"

echo -e "${RED}"

sudo python3 -m pip install awscli

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                            Installing Shodan                          #"
echo "   #########################################################################"

echo -e "${RED}"

sudo pip install shodan

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing Masscan                          #"
echo "   #########################################################################"

echo -e "${RED}"

git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
make install
mv list/resolvers.txt ~/Tools
cd ../
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                          Installing Findomain                         #"
echo "   #########################################################################"

echo -e "${RED}"

curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip
unzip findomain-linux-i386.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/findomain
sudo rm -rf findomain-linux-i386.zip
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing Ctfr                             #"
echo "   #########################################################################"

echo -e "${RED}"

git clone https://github.com/UnaPibaGeek/ctfr.git
cd ctfr
pip3 install -r requirements.txt
cd ../
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                        Installing Cloud_enum                          #"
echo "   #########################################################################"

echo -e "${RED}"

git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt
cd ../
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                         Installing ParamSpider                        #"
echo "   #########################################################################"

echo -e "${RED}"

git clone https://github.com/devanshbatham/ParamSpider.git
cd ParamSpider
pip3 install -r requirements.txt
cd ../
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                            Installing Kxss                            #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/Emoe/kxss@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                            Installing Dalfox                          #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/hahwul/dalfox/v2@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                            Installing ffuf                            #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/ffuf/ffuf@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing s3scanner                        #"
echo "   #########################################################################"

echo -e "${RED}"

pip3 install s3scanner
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing Sublist3r                        #"
echo "   #########################################################################"

echo -e "${RED}"

git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r
sudo pip install -r requirements.txt
cd ../
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing subfinder                        #"
echo "   #########################################################################"

echo -e "${RED}"

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                          Installing assetfinder                       #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/tomnomnom/assetfinder@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                             Installing Amass                          #"
echo "   #########################################################################"

echo -e "${RED}"

go install -v github.com/OWASP/Amass/v3/...@master
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                        Installing github-subdomains                   #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/gwen001/github-subdomains@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                        Installing github-endpoints                    #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/gwen001/github-endpoints@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                            Installing subjack                         #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/haccer/subjack@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing SubOver                          #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/Ice3man543/SubOver@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing gau                              #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/lc/gau/v2/cmd/gau@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing katana                           #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/projectdiscovery/katana/cmd/katana@latest

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing subjs                            #"
echo "   #########################################################################"

echo -e "${RED}"

GO111MODULE=on go install -v github.com/lc/subjs@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                            Installing getJS                           #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/003random/getJS@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing crobat                           #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/cgboal/sonarsearch/cmd/crobat@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing httpx                            #"
echo "   #########################################################################"

echo -e "${RED}"

go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                          Installing waybackurls                       #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/tomnomnom/waybackurls@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                             Installing gf                             #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/tomnomnom/gf@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                             Installing naabu                          #"
echo "   #########################################################################"

echo -e "${RED}"

go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                             Installing anew                           #"
echo "   #########################################################################"

echo -e "${RED}"

go install -v github.com/tomnomnom/anew@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                             Installing uro                            #"
echo "   #########################################################################"

echo -e "${RED}"

pip3 install uro
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing gobuster                         #"
echo "   #########################################################################"

echo -e "${RED}"

go install github.com/OJ/gobuster/v3@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                            Installing nuclei                          #"
echo "   #########################################################################"

echo -e "${RED}"

go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
clear

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                        Installing nuclei-templates                    #"
echo "   #########################################################################"

echo -e "${RED}"

git clone https://github.com/projectdiscovery/nuclei-templates.git
clear

mv ~/go/bin/* /usr/local/bin

mkdir ~/Tools

mv nuclei-templates Sublist3r ParamSpider cloud_enum ctfr ~/Tools

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing RustScan                         #"
echo "   #########################################################################"

echo -e "${RED}"

wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb

dpkg -i rustscan_2.0.1_amd64.deb

rm -rf rustscan_2.0.1_amd64.deb

wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json

wget https://raw.githubusercontent.com/Ice3man543/SubOver/master/providers.json
clear

mkdir ~/Tools/config

mv fingerprints.json providers.json ~/Tools/config

mkdir ~/Wordlists

echo -e "${BOLDGREEN}"

echo "   #########################################################################"
echo "   #                           Installing Wordlists                        #"
echo "   #########################################################################"

echo -e "${RED}"

wget https://raw.githubusercontent.com/0xmarWan7A/Eagle-Eye/main/Fuzz.txt
clear

mv Fuzz.txt ~/Wordlists

echo "   #########################################################################"
echo "   #                        -_- Finished Installing -_-                    #"
echo "   #########################################################################"

echo -e "${ENDCOLOR}"
