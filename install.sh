#!/usr/bin/env bash

wget https://go.dev/dl/go1.18.1.linux-amd64.tar.gz

rm -rf /usr/local/go && tar -C /usr/local -xzf go1.18.1.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin

rm -rf go1.18.1.linux-amd64.tar.gz

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


