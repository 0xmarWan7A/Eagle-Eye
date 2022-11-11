#!/usr/bin/env python3

from termcolor import colored
import subprocess
import time
import os
import os.path
import optparse

os.system("clear")

def banner():

        print("")
        print(colored("============================================================================", "blue", attrs=['bold']))
        print(colored("                             ///,        ////                              = ", "blue", attrs=['bold']))
        print(colored("                             \  /,      /  >.                              = ", "blue", attrs=['bold']))
        print(colored("                              \  /,   _/  /.                               = ", "blue", attrs=['bold']))
        print(colored("                               \_  /_/   /.                                = ", "blue", attrs=['bold']))
        print(colored("                                \__/_   <    Eagle                         = ", "blue", attrs=['bold']))
        print(colored("                                /<<< \_\_       Eye                        = ", "blue", attrs=['bold']))
        print(colored("                               /,)^>>_._ /                                 = ", "blue", attrs=['bold']))
        print(colored("                               (/   \\ /\\/                                  = ", "blue", attrs=['bold']))
        print(colored("                                    // ````                                = ", "blue", attrs=['bold']))
        print(colored("                          =========((`==========                           = ", "blue", attrs=['bold']))
        print(colored("                          Coded by: Marwan7assAan                          = ", "blue", attrs=['bold']))
        print(colored("                          Github: https://github.com/0xmarWan7A/           = ", "blue", attrs=['bold']))
        print(colored("                          Blog: https://marwanhassan.medium.com/           = ", "blue", attrs=['bold']))
        print(colored("                          Twitter: https://twitter.com/0xmarWan7A/         = ", "blue", attrs=['bold']))
        print(colored("                          Contact Me: m5500volly@gmail.com                 =  ", "blue", attrs=['bold']))
        print(colored("============================================================================", "blue", attrs=['bold']))
        print("")                                                                                                                                                                   
                                                                                                                                                                                                                                                                               
banner()


def User_input():

    parser = optparse.OptionParser()
    parser.add_option("-t","--target_domain",dest="target_domain",help="\tTarget Domain (google.com , yahoo.com)")
    (options,args) = parser.parse_args()
    if not options.target_domain:
        print(colored("Erorr : Target Domain dosen't exists , enter --help for more info" , "red" , attrs=['bold']))
        print(colored("Usage : python3 eagle-eye.py -t <Domain>" , "red" , attrs=['bold']))
        print("")
        raise SystemExit
    else:
        
        return options.target_domain

#target

user_input = User_input()
target = user_input
target_name = target.split(".")[0]


# Get Access Tokens & Create Main Directory


if os.path.exists("github_token.txt"):
    print(colored("[+] Github token already exists", "green", attrs=['bold']))
    with open("github_token.txt", "r") as f:
        github_token = f.read()
        f.close()
    print("")
    if os.path.isdir(target_name):
        pass
    else:
        print(colored("[+] Creating " + target_name + " Directory .......", "blue", attrs=['bold']))
        subprocess.call("mkdir " + target_name, shell=True)
        print("")
        print(colored("[+] Change directory to " + target_name , "blue", attrs=['bold']))
        os.chdir(target_name)
        print("")
        time.sleep(3)
        pass
else:
    github_token = input(colored("[+] Enter your github access token : " , "blue", attrs=['bold']))
    time.sleep(2)
    with open("github_token.txt" , "w") as f:
        f.write(github_token)
        f.close()
    print("")
    print(colored("[+] Done! Github token saved successfully", "green", attrs=['bold']))
    print("")
    print(colored("[+] Creating " + target_name + " Directory .......", "blue", attrs=['bold']))
    subprocess.call("mkdir " + target_name, shell=True)
    print("")
    print(colored("[+] Change directory to " + target_name , "blue", attrs=['bold']))
    os.chdir(target_name)
    print("")
    time.sleep(2)

# if os.path.exists("shodan_api.txt"):
#     print(colored("\n[+] Shodan API key already exists\n", "green", attrs=['bold']))
#     time.sleep(2)
#     pass

# else:
#     shodan_api = input(colored("\n[+] Enter your shodan api key : ", "blue", attrs=['bold']))
#     time.sleep(2)
#     if shodan_api:
#         subprocess.call("\nshodan init " + shodan_api , shell=True)
#         with open("shodan_api.txt", "w") as f:
#             f.write(shodan_api)
#             f.close()
#             print(colored("\n[+] Done! Shodan API key saved successfully\n\n", "green", attrs=['bold']))
#             time.sleep(2)

# Type Of Scan

print(colored("[1] deep", "yellow", attrs=['bold']))
print(colored("[2] fast", "yellow", attrs=['bold']))
print("")
Scan = input(colored("[+] Do you want deep or fast scan : " , "blue", attrs=['bold']))
subprocess.call("clear" , shell=True)
time.sleep(3)


def Sub_Domains():

    if os.path.isdir("subdomains"):
        os.chdir("subdomains")
        if os.path.exists("hosts.txt"):
            pass
    else:
        subprocess.call("mkdir subdomains" ,shell=True)
        os.chdir("subdomains")
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                           Subdomain Enumeration                       #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        if Scan == "1":
            print(colored("                          ##### Subfinder #####                                    ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("subfinder -silent -all -d " + target + " -o subfinder.txt 2>/dev/null", shell=True )
            print("")
            print("")
            print(colored("                          ##### Sublist3r #####                                       ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("python3 ~/Tools/Sublist3r/sublist3r.py -t 4 -d " + target + " -o sublist3r.txt 2>/dev/null" ,  shell=True)
            print("")
            print("")
            print(colored("                         ##### Assetfinder #####                                     ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("assetfinder -subs-only " + target + " | anew assetfinder.txt 2>/dev/null", shell=True )
            print("")
            print("")
            print(colored("                             ##### Findomain #####                                          ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("findomain -t " + target + " -u findomain.txt 2>/dev/null" ,shell=True)
            print("")
            print("")
            print(colored("                             ##### Amass #####                                          ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("amass enum -passive -norecursive -noalts -d " + target + " -o amass_passive.txt 2>/dev/null" , shell=True)
            print("")
            print("")
            print(colored("                          ##### Github-SubDomains #####                               ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("github-subdomains -k -d " + target + " -t " + github_token, shell=True)
            print("")
            print("")
            print(colored("                               ##### Crobat #####                               ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("crobat -s " + target + " | anew crobat.txt 2>/dev/null", shell=True)
            print("")
            print("")
            print(colored("                                ##### Curl #####                               ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("curl -s -k 'https://jldc.me/anubis/subdomains/" + target + "'" + " | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | sed '/^\./d' | anew curl.txt 2>/dev/null", shell=True)
            subprocess.call("curl -s -k 'https://dns.bufferover.run/dns?q=." + target + "'" + " | jq -r '.FDNS_A'[],'.RDNS'[] | cut -d ',' -f2 | grep -F " + "'" + "." + target + "' | anew curl.txt 2>/dev/null", shell=True)
            subprocess.call("curl -s -k 'https://tls.bufferover.run/dns?q=." + target + "'" + " | jq -r .Results[] | cut -d ',' -f4 | grep -F " + "'" + "." + target + "' | anew curl.txt 2>/dev/null", shell=True)
            print("")
            print("")
            print(colored("                      ##### Crtsh Subdomain Enumeration #####                        ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("python3 ~/Tools/ctfr/ctfr.py -d " + target + " -o crtsh.txt", shell=True)
            print("")
            print("")
            print(colored("   #########################################################################", "red", attrs=['bold']))
            print(colored("   #                       Start Collecting Live Subdomains                #", "red", attrs=['bold']))
            print(colored("   #########################################################################", "red", attrs=['bold']))
            print("")
            time.sleep(5)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("cat *.txt | sort -u | anew subdomains.txt",shell=True)
            subprocess.call("rm -rf subfinder.txt sublist3r.txt assetfinder.txt findomain.txt amass_passive.txt amass_active.txt crtsh.txt crobat.txt curl.txt " + target + ".txt ",shell=True)
            subprocess.call("cat subdomains.txt | httpx -silent -t 250 -o hosts.txt",shell=True)
            subprocess.call("clear" ,shell=True)
        elif Scan == "2":
            print(colored("                            ##### Subfinder #####                                       ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("subfinder -silent -d " + target + " -o subfinder.txt ", shell=True )
            print("")
            print(colored("                            ##### Sublist3r #####                                       ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("python3 ~/Tools/Sublist3r/sublist3r.py -t 4 -d " + target + " -o sublist3r.txt 2>/dev/null" ,  shell=True)
            print("")
            print(colored("                            ##### Assetfinder #####                                     ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("assetfinder -subs-only " + target + " | anew assetfinder.txt 2>/dev/null", shell=True )
            print("")
            print(colored("                             ##### Findomain #####                                          ", "blue", attrs=['bold']))
            time.sleep(3)
            os.system("echo -e '\e[1;32m'")
            subprocess.call("findomain -t " + target + " -u findomain_result.txt " ,shell=True)
            print("")
            print(colored("   #########################################################################", "red", attrs=['bold']))
            print(colored("   #                       Start Collecting Live Subdomains                #", "red", attrs=['bold']))
            print(colored("   #########################################################################", "red", attrs=['bold']))
            os.system("echo -e '\e[1;32m'")
            time.sleep(5)
            subprocess.call("cat *.txt | sort -u | anew subdomains.txt",shell=True)
            subprocess.call("rm -rf subfinder.txt sublist3r.txt assetfinder.txt findomain.txt",shell=True)
            subprocess.call("cat subdomains.txt | httpx -silent -t 250 -o hosts.txt",shell=True)
            subprocess.call("clear" ,shell=True)
        else:
            print(colored("[-] Wrong Number !! ", "red", attrs=['bold']))
            Sub_Domains()

Sub_Domains()

def Collect_ips():

    if os.path.exists("ips.txt"):
        pass
    else:
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                             Searching For IPs                         #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("", "red", attrs=['bold']))
        time.sleep(5)
        os.system("echo -e '\e[1;32m'")
        subprocess.call("cat hosts.txt | httpx -silent -pa -t 300 -o ip.txt", shell=True)
        subprocess.call("shodan search hostname:" + target + " | awk '{print $1}' | anew shodan_ips.txt", shell=True)
        subprocess.call("shodan search ssl:" + target + ".* | awk '{print $1}' | anew shodan_ips.txt", shell=True)
        subprocess.call("shodan search ssl.cert.subject.CN:" + target + ".* 200 | awk '{print $1}' | anew shodan_ips.txt", shell=True)
        subprocess.call("cat ip.txt | cut -d '[' -f 2 | cut -d ']' -f 1 | anew ips.txt" , shell=True)
        subprocess.call("cat shodan_ips.txt | sort -u | anew ips.txt" ,shell=True)
        subprocess.call("rm -rf shodan_ips.txt", shell=True)
        subprocess.call("rm -rf ip.txt", shell=True)
        subprocess.call("clear" ,shell=True)

Collect_ips()

#Searching for subdomain takeover

def Subdomain_TakeOver():

    if os.path.isdir("Subdomain_TakeOver"):
        if os.path.exists("Subdomain_TakeOver/subdomain_takeover.txt"):
            pass
    else:
        subprocess.call("mkdir Subdomain_TakeOver " , shell=True)
        #os.chdir("Subdomain_TakeOver")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                       Searching For Subdomain-TakeOver                #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        print(colored("                             ##### SubJack #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        subprocess.call("subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c ~/Tools/config/fingerprints.json -a -v -m -o Subdomain_TakeOver/subjack1.txt", shell=True)
        subprocess.call("cat Subdomain_TakeOver/subjack1.txt | grep -v 'Not Vulnerable' | anew Subdomain_TakeOver/subjack.txt ", shell=True)
        subprocess.call("rm -rf Subdomain_TakeOver/subjack1.txt", shell=True)
        print("")
        print(colored("                             ##### SubOver #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        subprocess.call("cp ~/Tools/config/providers.json ." , shell=True)
        subprocess.call("SubOver -l subdomains.txt -a -t 100 -v -https -timeout 30 | anew Subdomain_TakeOver/subover.txt " ,shell=True)
        subprocess.call("cat Subdomain_TakeOver/subover.txt Subdomain_TakeOver/subjack.txt | anew Subdomain_TakeOver/subdomain_takeover.txt " ,shell=True)
        subprocess.call("rm -rf Subdomain_TakeOver/subover.txt Subdomain_TakeOver/subjack.txt " ,shell=True)
        #subprocess.call("cd ../ " ,shell=True)
        subprocess.call("clear", shell=True)

Subdomain_TakeOver()


def S3bucket():
    if os.path.isdir("S3Bucket_misconfiguration"):
        if os.path.exists("S3Bucket_misconfiguration/s3scanner.txt"):
            pass
    else:
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                       Searching For AWS S3 Bucket                     #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        subprocess.call("mkdir S3Bucket_misconfiguration", shell=True)
        #os.chdir("S3Bucket_misconfiguration")
        print("")
        print(colored("                             ##### S3scanner #####                             ", "blue", attrs=['bold']))
        time.sleep(3)
        subprocess.call("s3scanner scan -f hosts.txt | anew S3Bucket_misconfiguration/s3scanner.txt" , shell=True)
        print("")
        print(colored("                             ##### Cloud enum #####                             ", "blue", attrs=['bold']))
        time.sleep(3)
        subprocess.call("python3 ~/Tools/cloud_enum/cloud_enum.py -kf hosts.txt -qs -t 10 | anew S3Bucket_misconfiguration/cloud_enum.txt" ,shell=True)
        #subprocess.call("cd ../", shell=True)
        subprocess.call("clear", shell=True)

S3bucket()


#collect all live endpoints


def End_Points():

    if os.path.isdir("Content-Discovery"):
        if os.path.exists("Content-Discovery/endpoints.txt"):
            pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                         Start Collecting End_Points                   #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        subprocess.call("mkdir Content-Discovery", shell=True)
        #os.chdir("Content-Discovery")
        print("")
        print(colored("                             ##### Waybackurls #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        os.system("echo -e '\e[1;32m'")
        subprocess.call("cat hosts.txt | waybackurls | grep -i -v -e .doc -e .docx -e .pdf -e .css -e .jpg -e .gif -e .jpeg -e .png -e .svg -e .ico -e .wav -e .mp3 -e .mp4 | anew Content-Discovery/waybackurls_output.txt",shell=True)
        print("")
        subprocess.call("cat Content-Discovery/waybackurls_output.txt | sort -u | uro  | anew Content-Discovery/wayback.txt" , shell=True)
        subprocess.call("rm -rf Content-Discovery/waybackurls_output.txt" , shell=True )
        print("")
        print(colored("                             ##### Github-Endpoints #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        subprocess.call("github-endpoints -t " + github_token + " -d " + target ,shell=True)
        subprocess.call("mv " + target + ".txt github_endpoints.txt" , shell=True)
        subprocess.call("mv github_endpoints.txt Content-Discovery/" , shell=True)
        subprocess.call("cat Content-Discovery/github_endpoints.txt | sort -u | uro | anew Content-Discovery/github.txt ",shell=True)
        subprocess.call("rm -rf Content-Discovery/github_endpoints.txt " ,shell=True)
        print("")
        print(colored("                                   ##### Gau #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        os.system("echo -e '\e[1;32m'")
        subprocess.call("cat hosts.txt | gau --subs --threads 30 --blacklist png,jpg,gif,jpeg,css,svg,ico,wav,mp3,mp4,doc,docx,pdf --mc 200 --o Content-Discovery/gau_output.txt",shell=True)
        print("")
        subprocess.call("cat Content-Discovery/gau_output.txt | sort -u | uro  | anew Content-Discovery/gau.txt" , shell=True)
        subprocess.call("rm -rf Content-Discovery/gau_output.txt" , shell=True )
        subprocess.call("cat Content-Discovery/*.txt | sort -u | uro | anew Content-Discovery/endpoints.txt" ,shell=True)
        subprocess.call("rm -rf Content-Discovery/gau.txt Content-Discovery/github.txt Content-Discovery/wayback.txt", shell=True)
        subprocess.call("clear", shell=True)

End_Points()

#extract all javascript files

def Extract_JSFiles():

    if os.path.exists("Content-Discovery/jsfiles.txt"):
        pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                         Start Extracting JS Files                     #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        os.system("echo -e '\e[1;32m'")
        subprocess.call("cat hosts.txt | getJS --complete --resolve --insecure --output Content-Discovery/getJS.txt" , shell=True)
        subprocess.call("subfinder -d " + target + " -silent | httpx | subjs | anew Content-Discovery/js-files.txt" , shell=True)
        subprocess.call("cat hosts.txt | katana -silent -em js -o Content-Discovery/katanajs.txt",shell=True)
        subprocess.call("cat Content-Discovery/js-files.txt Content-Discovery/getJS.txt Content-Discovery/katanajs.txt | sort -u | uro | anew Content-Discovery/jsfiles.txt " ,shell=True)
        subprocess.call("rm -rf Content-Discovery/js-files.txt Content-Discovery/getJS.txt Content-Discovery/katanajs.txt" ,shell=True)
        subprocess.call("clear", shell=True)

Extract_JSFiles()

#extract juicy data from js-files

def Secret_Finder():

    if os.path.exists("Content-Discovery/Secret-Tokens.txt"):
        pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                Start Extracting Juicy Data From JSFiles               #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        print("")
        print(colored("                                   ##### Nuclei #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        subprocess.call("cat Content-Discovery/jsfiles.txt | nuclei -t ~/nuclei-templates/exposures -o Content-Discovery/Secret-Tokens.txt" , shell=True)
        #subprocess.call("cd ../",shell=True)
        subprocess.call("clear", shell=True)
Secret_Finder()

#extract all juicy files

def Extract_JuicyFiles():
    if os.path.exists("Content-Discovery/juicy-files.txt"):
        pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                       Start Extracting Juicy Files                    #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        subprocess.call("cat hosts.txt | katana -silent -d 5 -em php, sql, tar, zip, rar, bak, gz, conf, config, yaml, sh, py, xml, info, json, pl, rb, csv, xls, xlsx, txt -o Content-Discovery/juicy-files.txt" , shell=True)
        # subprocess.call("cd ../",shell=True)
        subprocess.call("clear", shell=True)
Extract_JSFiles()


#search for reflected xss

def Reflected_XSS():

    if os.path.isdir("Reflected-XSS"):
        if os.path.exists("Reflected-XSS/params.txt"):
            pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                    Start Searching For Reflected XSS                  #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        subprocess.call("mkdir Reflected-XSS", shell=True)
        #os.chdir("Reflected-XSS")
        print("")
        print(colored("                           ##### ParamSpider && Kxss && dalfox #####                                  ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        subprocess.call("python3 ~/Tools/ParamSpider/paramspider.py -d " + target + " -l high" , shell=True)
        subprocess.call("mv output/" + target + ".txt Reflected-XSS/ && rm -rf output && mv Reflected-XSS/" + target + ".txt params.txt"  ,shell=True)
        subprocess.call("cat Reflected-XSS/params.txt | kxss | grep '< >' | cut -d ' ' -f 2 | anew Reflected-XSS/unfiltered.txt" ,shell=True)
        subprocess.call("dalfox file Reflected-XSS/unfiltered.txt --waf-evasion --user-agent -b 0xmarWan7A.xss.ht pipe -o Reflected-XSS/XSS_poc.txt" ,shell=True)
        #subprocess.call("cd ../", shell=True)
        subprocess.call("clear", shell=True)
Reflected_XSS()

def technologies_detect():
    if os.path.isdir("Technologies"):
        if os.path.exists("Technologies/technologies.txt"):
            pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                      Start Searching For Technologies                 #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        subprocess.call("mkdir Technologies", shell=True)
        #os.chdir("Technologies")
        print("")
        print(colored("                                   ##### nuclei #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        subprocess.call("cat hosts.txt | nuclei -t ~/nuclei-templates/technologies/ -o Technologies/technologies.txt" , shell=True)
        #subprocess.call("cd ../", shell=True)
        subprocess.call("clear", shell=True)
technologies_detect()

#bruteforcing directories using ffuf

def Directory_Fuzzing():
    if os.path.isdir("Fuzz"):
        if os.path.exists("Fuzz/dir.txt"):
            pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                         Start Fuzzing Directories                     #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        subprocess.call("mkdir Fuzz", shell=True)
        #os.chdir("Fuzz")
        print("")
        print(colored("                                   ##### FFUF #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        subprocess.call("ffuf -u HFUZZ:WFUZZ -X POST -w hosts.txt:HFUZZ -w ~/Wordlists/Fuzz.txt:WFUZZ -t 50 -c -v -r -mc 200,403 -o Fuzz/dir.txt" ,shell=True)
        #subprocess.call("cd ../", shell=True)
        subprocess.call("clear", shell=True)
Directory_Fuzzing() 


# port scan

def Port_Scanning():
    if os.path.isdir("Port-Scan"):
        if os.path.exists("Port-Scan/open_ports.txt"):
            pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                             Start Port Scanning                       #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        subprocess.call("mkdir Port-Scan" ,shell=True)
        #os.chdir("Port-Scan")
        print("")
        print(colored("                                   ##### Rustscan #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        subprocess.call("rustscan -a 'ips.txt' --ulimit 10000 | grep 'Open' | sed 's/Open //' | anew Port-Scan/open_ports.txt  " , shell=True)
        #subprocess.call("cd ../", shell=True)
        subprocess.call("clear", shell=True)
Port_Scanning()


#scan vulnerabilities

def Vulnerabilities():
    if os.path.isdir("Vulnerabilities"):
        if os.path.exists("Vulnerabilities/Vulnerabilities.txt"):
            pass
    else:
        print("")
        print("")
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print(colored("   #                     Start Scanning For Vulnerabilities                #", "red", attrs=['bold']))
        print(colored("   #########################################################################", "red", attrs=['bold']))
        print("")
        time.sleep(5)
        subprocess.call("mkdir Vulnerabilities", shell=True)
        #os.chdir("Vulnerabilities")
        print("")
        print(colored("                                   ##### Nuclei #####                                    ", "blue", attrs=['bold']))
        time.sleep(3)
        print("")
        try:
            subprocess.call("nuclei -l hosts.txt -t ~/nuclei-templates/ -et ~/nuclei-templates/technologies/ -et ~/nuclei-templates/takeovers/ -o Vulnerabilities/Vulnerabilities.txt" ,shell=True)
            subprocess.call("cat Vulnerabilities/Vulnerabilities.txt | grep -i 'info' | anew Vulnerabilities/info.txt ", shell=True)
            subprocess.call("cat Vulnerabilities/Vulnerabilities.txt | grep -i 'low' | anew Vulnerabilities/low.txt ", shell=True)
            subprocess.call("cat Vulnerabilities/Vulnerabilities.txt | grep -i 'medium' | anew Vulnerabilities/medium.txt ", shell=True)
            subprocess.call("cat Vulnerabilities/Vulnerabilities.txt | grep -i 'high' | anew Vulnerabilities/high.txt ", shell=True)
            subprocess.call("cat Vulnerabilities/Vulnerabilities.txt | grep -i 'critical' | anew Vulnerabilities/critical.txt ", shell=True)
            subprocess.call("cat Vulnerabilities/Vulnerabilities.txt | grep -i 'unknown' | anew Vulnerabilities/unknown.txt ", shell=True)
            #subprocess.call("cd ../" ,shell=True)
            subprocess.call("clear", shell=True)
        except Exception as e:
            print(colored("[-] Error has occured !" + e, "red", attrs=['bold']))
            pass

Vulnerabilities()
