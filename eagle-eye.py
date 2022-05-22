#!/usr/bin/env python3

import subprocess
import time
import os
import optparse

def banner():

        print("")
        print("============================================================================")
        print("                             ///,        ////                              = ")
        print("                             \  /,      /  >.                              = ")
        print("                              \  /,   _/  /.                               = ")
        print("                               \_  /_/   /.                                = ")
        print("                                \__/_   <    Eagle                         = ")
        print("                                /<<< \_\_       Eye                        = ")
        print("                               /,)^>>_._ /                                 = ")
        print("                               (/   \\ /\\/                                  = ")
        print("                                    // ````                                = ")
        print("                          =========((`==========                           = ")
        print("                          Coded by: Marwan7assAan                          = ")
        print("                          Github: https://github.com/0xmarWan7A/           = ")
        print("                          Blog: https://marwanhassan.medium.com/           = ")
        print("                          Twitter: https://twitter.com/0xmarWan7A/         = ")
        print("                          Contact Me: m5500volly@gmail.com                 =  ")
        print("============================================================================")
        print("")                                                                                                                                                                   
                                                                                                                                                                                                                                                                                 
banner()


def User_input():

    parser = optparse.OptionParser()
    parser.add_option("-t","--target_domain",dest="target_domain",help="\tTarget Domain (google.com , yahoo.com)")
    (options,args) = parser.parse_args()
    if not options.target_domain:
        print("Erorr : Target Domain dosen't exists , enter --help for more info")
        print("Usage : python3 eagle-eye.py -t <Domain>")
        print("")
        raise SystemExit
    else:
        
        return options.target_domain

#target

user_input = User_input()
target = user_input
target_name = target.split(".")[0]


# Get Access Tokens & Create Main Directory

github_token = input("[+] Enter your github access token : ")
time.sleep(2)
with open("github_token.txt" , "w") as f:
	f.write(github_token)
	f.close()
print("[+] Done! Github token saved successfully")
print("")
print("[+] Creating " + target_name + " Directory .......")
subprocess.call("mkdir " + target_name, shell=True)
print("")
print("[+] Change directory to " + target_name)
os.chdir(target_name)
print("")
time.sleep(3)


# Type Of Scan

print("[1] deep")
print("[2] fast")
print("")
Scan = input("[+] Do you want deep or fast scan : ")
subprocess.call("clear" , shell=True)
time.sleep(3)


def Sub_Domains():

    subprocess.call("mkdir subdomains" ,shell=True)
    os.chdir("subdomains")
    print("")
    print("")
    print("   #########################################################################")
    print("   #                           Subdomain Enumeration                       #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    if Scan == "1":
        print("                          ##### Subfinder #####                                    ")
        time.sleep(3)
        print("")
        subprocess.call("subfinder -silent -all -d " + target + " -o subfinder.txt 2>/dev/null", shell=True )
        print("")
        print("")
        print("                          ##### Sublist3r #####                                       ")
        time.sleep(3)
        print("")
        subprocess.call("python3 ~/Tools/Sublist3r/sublist3r.py -t 4 -d " + target + " -o sublist3r.txt 2>/dev/null" ,  shell=True)
        print("")
        print("")
        print("                         ##### Assetfinder #####                                     ")
        time.sleep(3)
        print("")
        subprocess.call("assetfinder -subs-only " + target + " | anew assetfinder.txt 2>/dev/null", shell=True )
        print("")
        print("")
        print("                             ##### Findomain #####                                          ")
        time.sleep(3)
        print("")
        subprocess.call("findomain -t " + target + " -u findomain.txt 2>/dev/null" ,shell=True)
        print("")
        print("")
        print("                             ##### Amass #####                                          ")
        time.sleep(3)
        print("")
        subprocess.call("amass enum -passive -norecursive -noalts -d " + target + " -o amass_passive.txt 2>/dev/null" , shell=True)
        subprocess.call("amass enum -active -norecursive -noalts -d " + target + " -o amass_active.txt 2>/dev/null" , shell=True)
        print("")
        print("")
        print("                          ##### Github-SubDomains #####                               ")
        time.sleep(3)
        print("")
        subprocess.call("github-subdomains -k -d " + target + " -t " + github_token, shell=True)
        print("")
        print("")
        print("                               ##### Crobat #####                               ")
        time.sleep(3)
        print("")
        subprocess.call("crobat -s " + target + " | anew crobat.txt 2>/dev/null", shell=True)
        print("")
        print("")
        print("                                ##### Curl #####                               ")
        time.sleep(3)
        print("")
        subprocess.call("curl -s -k 'https://jldc.me/anubis/subdomains/" + target + "'" + " | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | sed '/^\./d' | anew curl.txt 2>/dev/null", shell=True)
        subprocess.call("curl -s -k 'https://dns.bufferover.run/dns?q=." + target + "'" + " | jq -r '.FDNS_A'[],'.RDNS'[] | cut -d ',' -f2 | grep -F " + "'" + "." + target + "' | anew curl.txt 2>/dev/null", shell=True)
        subprocess.call("curl -s -k 'https://tls.bufferover.run/dns?q=." + target + "'" + " | jq -r .Results[] | cut -d ',' -f4 | grep -F " + "'" + "." + target + "' | anew curl.txt 2>/dev/null", shell=True)
        print("")
        print("")
        print("                      ##### Crtsh Subdomain Enumeration #####                        ")
        time.sleep(3)
        print("")
        subprocess.call("python3 ~/Tools/ctfr/ctfr.py -d " + target + " -o crtsh.txt", shell=True)
        print("")
        print("")
        print("   #########################################################################")
        print("   #                       Start Collecting Live Subdomains                #")
        print("   #########################################################################")
        print("")
        time.sleep(5)
        subprocess.call("cat *.txt | sort -u | anew subdomains.txt",shell=True)
        subprocess.call("rm -rf subfinder.txt sublist3r.txt assetfinder.txt findomain.txt amass_passive.txt amass_active.txt crtsh.txt crobat.txt curl.txt",shell=True)
        subprocess.call("cat subdomains.txt | httpx -silent -t 250 -o hosts.txt",shell=True)
        subprocess.call("clear" ,shell=True)
    elif Scan == "2":
        print("                            ##### Subfinder #####                                       ")
        time.sleep(3)
        print("")
        subprocess.call("subfinder -silent -d " + target + " -o subfinder.txt ", shell=True )
        print("")
        print("                            ##### Sublist3r #####                                       ")
        time.sleep(3)
        print("")
        subprocess.call("python3 ~/Tools/Sublist3r/sublist3r.py -t 4 -d " + target + " -o sublist3r.txt 2>/dev/null" ,  shell=True)
        print("")
        print("                            ##### Assetfinder #####                                     ")
        time.sleep(3)
        print("")
        subprocess.call("assetfinder -subs-only " + target + " | anew assetfinder.txt 2>/dev/null", shell=True )
        print("")
        print("                             ##### Findomain #####                                          ")
        time.sleep(3)
        print("")
        subprocess.call("findomain -t " + target + " -u findomain_result.txt " ,shell=True)
        print("")
        print("   #########################################################################")
        print("   #                       Start Collecting Live Subdomains                #")
        print("   #########################################################################")
        print("")
        time.sleep(5)
        subprocess.call("cat *.txt | sort -u | anew subdomains.txt",shell=True)
        subprocess.call("rm -rf subfinder.txt sublist3r.txt assetfinder.txt findomain.txt",shell=True)
        subprocess.call("cat subdomains.txt | httpx -silent -t 250 -o hosts.txt",shell=True)
        subprocess.call("clear" ,shell=True)
    else:
        print("[-] Wrong Number !! ")
        Sub_Domains()

Sub_Domains()

def Collect_ips():
    print("   #########################################################################")
    print("   #                             Searching For IPs                         #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("cat hosts.txt | httpx -silent -pa -t 300 -o ip.txt", shell=True)
    subprocess.call("cat ip.txt | cut -d '[' -f 2 | cut -d ']' -f 1 | anew ips.txt" , shell=True)
    subprocess.call("rm -rf ip.txt", shell=True)
    subprocess.call("clear" ,shell=True)

Collect_ips()

#Searching for subdomain takeover

def Subdomain_TakeOver():
    print("   #########################################################################")
    print("   #                       Searching For Subdomain-TakeOver                #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir Subdomain_TakeOver " , shell=True)
    os.chdir("Subdomain_TakeOver")
    print("                             ##### SubJack #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("subjack -w ../subdomains.txt -t 100 -timeout 30 -ssl -c /usr/share/subjack/fingerprints.json -a -v -m -o subjack1.txt", shell=True)
    subprocess.call("cat subjack1.txt | grep -v 'Not Vulnerable' | anew subjack.txt ", shell=True)
    subprocess.call("rm -rf subjack1.txt", shell=True)
    print("")
    print("                             ##### SubOver #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("SubOver -l ../subdomains.txt -a -t 100 -v -https -timeout 30 | anew subover.txt " ,shell=True)
    print("")
    print("                              ##### Nuclei #####                                       ")
    time.sleep(3)
    print("")
    subprocess.call("cat ../subdomains.txt | nuclei ~/nuclei-templates/takeovers/ -o nuclei.txt" ,shell=True)
    subprocess.call("cat subover.txt subjack.txt nuclei.txt | anew subdomain_takeover.txt " ,shell=True)
    subprocess.call("rm -rf subover.txt subjack.txt nuclei.txt" ,shell=True)
    subprocess.call("cd ../ " ,shell=True)
    subprocess.call("clear", shell=True)

Subdomain_TakeOver()


def S3bucket():
    print("   #########################################################################")
    print("   #                       Searching For AWS S3 Bucket                     #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir S3Bucket_misconfiguration", shell=True)
    os.chdir("S3Bucket_misconfiguration")
    print("")
    print("                             ##### S3scanner #####                             ")
    time.sleep(3)
    subprocess.call("s3scanner scan -f ../hosts.txt " , shell=True)
    print("")
    print("                             ##### Cloud enum #####                             ")
    time.sleep(3)
    subprocess.call("python3 ~/Tools/cloud_enum/cloud_enum.py -kf ../hosts.txt -qs -t 10 " ,shell=True)
    subprocess.call("cd ../", shell=True)
    subprocess.call("clear", shell=True)

S3bucket()


#collect all live endpoints


def End_Points():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                         Start Collecting End_Points                   #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir Content-Discovery", shell=True)
    os.chdir("Content-Discovery")
    print("")
    print("                             ##### Waybackurls #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("cat ../hosts.txt | waybackurls | grep -i -v -e .doc -e .docx -e .pdf -e .css -e .jpg -e .gif -e .jpeg -e .png -e .svg -e .ico -e .wav -e .mp3 -e .mp4 | anew waybackurls_output.txt",shell=True)
    print("")
    subprocess.call("cat waybackurls_output.txt | sort -u  | anew wayback.txt" , shell=True)
    subprocess.call("rm -rf waybackurls_output.txt" , shell=True )
    print("")
    print("                             ##### Github-Endpoints #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("python3 /usr/share/github-endpoints.py -t " + github_token + " -d " + target + " | anew github_endpoints.txt" ,shell=True)
    subprocess.call("cat github_endpoints.txt | sort -u | anew github.txt ",shell=True)
    subprocess.call("rm -rf github_endpoints.txt " ,shell=True)
    print("")
    print("                                   ##### Gau #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("cat ../hosts.txt | gau --subs --threads 30 --blacklist png,jpg,gif,jpeg,css,svg,ico,wav,mp3,mp4,doc,docx,pdf --mc 200 -o gau_output.txt",shell=True)
    print("")
    subprocess.call("cat gau_output.txt | sort -u  | anew gau.txt" , shell=True)
    subprocess.call("rm -rf gau_output.txt" , shell=True )
    subprocess.call("cat *.txt | sort -u | anew endpoints.txt" ,shell=True)
    subprocess.call("clear", shell=True)

End_Points()

#extract all javascript files

def Extract_JSFiles():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                         Start Extracting JS Files                     #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("cat endpoints.txt | grep '.js$' | anew js-files.txt " , shell=True)
    subprocess.call("subfinder -d " + target + " -silent | httpx | subjs | anew js-files.txt" , shell=True)
    subprocess.call("cat js-files.txt |sort -u | anew jsfiles.txt " ,shell=True)
    subprocess.call("rm -rf js-files.txt" ,shell=True)
    subprocess.call("clear", shell=True)
Extract_JSFiles()

#extract juicy data from js-files

def Secret_Finder():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                Start Extracting Juicy Data From JSFiles               #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    print("")
    print("                                   ##### Nuclei #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("cat jsfiles.txt | nuclei -t ~/nuclei-templates/exposures -o Secret-Tokens.txt" , shell=True)
    subprocess.call("cd ../",shell=True)
    subprocess.call("clear", shell=True)
Secret_Finder()

#extract all juicy files

def Extract_JuicyFiles():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                       Start Extracting Juicy Files                    #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("cat endpoints.txt | grep '.php$' | grep '.sql$' | grep '.tar$' | grep '.zip$' | grep '.rar$' | grep '.bak$' | grep '.gz$' | grep '.conf$' | grep '.config$' | grep '.yaml$' | grep '.sh$' | grep '.py$' | grep '.xml' | grep '.info$' | grep '.json$' | grep '.pl$' | grep '.rb$' | grep '.csv$' | grep '.xls$' | grep '.xlsx$' | grep '.txt$' | anew juicy-files.txt " , shell=True)
    subprocess.call("cat juicy-files.txt |sort -u | anew juicy_files.txt " ,shell=True)
    subprocess.call("rm -rf juicy-files.txt" ,shell=True)
    subprocess.call("cd ../",shell=True)
    subprocess.call("clear", shell=True)
Extract_JSFiles()


#search for reflected xss

def Reflected_XSS():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                    Start Searching For Reflected XSS                  #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir Reflected-XSS", shell=True)
    os.chdir("Reflected-XSS")
    print("")
    print("                           ##### ParamSpider && Kxss && dalfox #####                                  ")
    time.sleep(3)
    print("")
    subprocess.call("python3 ~/Tools/ParamSpider/paramspider.py -d " + target + " -l high" , shell=True)
    subprocess.call("mv " + target + ".txt . && rm -rf output && mv " + target + ".txt params.txt"  ,shell=True)
    subprocess.call("cat params.txt | kxss | grep '< >' | cut -d ' ' -f 2 | anew unfiltered.txt" ,shell=True)
    subprocess.call("dalfox file unfiltered.txt --waf-evasion --user-agent -b 0xmarWan7A.xss.ht pipe -o XSS_poc.txt" ,shell=True)
    subprocess.call("cd ../", shell=True)
    subprocess.call("clear", shell=True)
Reflected_XSS()

def technologies_detect():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                      Start Searching For Technologies                 #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir Technologies", shell=True)
    os.chdir("Technologies")
    print("")
    print("                                   ##### nuclei #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("cat ../hosts.txt | nuclei -t ~/nuclei-templates/technologies/ -o technologies.txt" , shell=True)
    subprocess.call("cd ../", shell=True)
    subprocess.call("clear", shell=True)
technologies_detect()

#bruteforcing directories using ffuf

def Directory_Fuzzing():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                         Start Fuzzing Directories                     #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir Fuzz", shell=True)
    os.chdir("Fuzz")
    print("")
    print("                                   ##### FFUF #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("ffuf -u HFUZZ:WFUZZ -X POST -w ../hosts.txt:HFUZZ -w ~/Wordlists/Fuzz.txt:WFUZZ -t 50 -c -v -r -o dir.txt" ,shell=True)
    subprocess.call("cd ../", shell=True)
    subprocess.call("clear", shell=True)
Directory_Fuzzing() 


# port scan

def Port_Scanning():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                             Start Port Scanning                       #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir Port-Scan" ,shell=True)
    os.chdir("Port-Scan")
    print("")
    print("                                   ##### Rustscan #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("rustscan -a '../ips.txt' --no-nmap --ulimit 10000 | grep 'Open' | sed 's/Open //' | anew open_ports.txt  " , shell=True)
    subprocess.call("cd ../", shell=True)
    subprocess.call("clear", shell=True)
Port_Scanning()


#scan vulnerabilities

def Vulnerabilities():
    print("")
    print("")
    print("   #########################################################################")
    print("   #                     Start Scanning For Vulnerabilities                #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir Vulnerabilities", shell=True)
    os.chdir("Vulnerabilities")
    print("")
    print("                                   ##### Nuclei #####                                    ")
    time.sleep(3)
    print("")
    try:
        subprocess.call("nuclei -l ../hosts.txt -t ~/nuclei-templates/ -et ~/nuclei-templates/technologies/ -et ~/nuclei-templates/takeovers/ -v -o Vulnerabilities.txt" ,shell=True)
        subprocess.call("cat Vulnerabilities | grep -i 'info' | anew info.txt ", shell=True)
        subprocess.call("cat Vulnerabilities | grep -i 'low' | anew low.txt ", shell=True)
        subprocess.call("cat Vulnerabilities | grep -i 'medium' | anew medium.txt ", shell=True)
        subprocess.call("cat Vulnerabilities | grep -i 'high' | anew high.txt ", shell=True)
        subprocess.call("cat Vulnerabilities | grep -i 'critical' | anew critical.txt ", shell=True)
        subprocess.call("cat Vulnerabilities | grep -i 'unknown' | anew unknown.txt ", shell=True)
        subprocess.call("cd ../" ,shell=True)
        subprocess.call("clear", shell=True)
    except Exception as e:
        print("[-] Error has occured !" + e)
        pass

Vulnerabilities()
