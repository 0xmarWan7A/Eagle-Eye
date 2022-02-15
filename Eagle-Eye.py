#!/usr/bin/env python3

from tqdm import tqdm
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
        print("Usage : python3 eagle-eye.py -t <domain.com>")
        print("")
        raise SystemExit
    else:
        
        return options.target_domain

#target

user_input = User_input()
target = user_input
target_name = target.split(".")[0]

osint = "OSINT"
subdomains = "subdomains.txt"
resolved_subdomains = "resolved_subdomains.txt"
Live_subdoamins = "Live_subdomains.txt"
waybackurls_output = "waybackurls_ouyput.txt"
wayback = "wayback.txt"
jsfile = "javascript.txt"
dir = "directories.txt"
vuln = "vulnerable_files"
ssrf = "gf_ssrf.txt"
sqli = "gf_sqli.txt"
xss = "gf_xss.txt"
lfi = "gf_lfi.txt"
redirect = "gf_redirect.txt"
idor = "gf_idor.txt"
rce = "gf_rce.txt"
auto = "automation_scan"
port = "portSacnning.txt"


# Get Access Tokens & Create Main Directory
def get_access_tokens():

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
get_access_tokens()

# Type Of Scan
def Target_Scope():

	print("[1] deep")
	print("[2] fast")
	print("")
	Scan = input("[+] Do you want deep or fast scan : ")
	subprocess.call("clear" , shell=True)
	time.sleep(3)
Target_Scope()


#OSINT

def OSINT():

    print("   #########################################################################")
    print("   #                               Start OSINT                             #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir " + osint , shell=True)
    os.chdir(osint)
    print("                           ##### Domain Info #####                              ")
    time.sleep(3)
    print("")
    subprocess.call("lynx -dump https://domainbigdata.com/" + target + " | tali -n +19 " )
        
#collect subdomains

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
        subprocess.call("cat subfinder.txt > " + subdomains, shell=True)
        subprocess.call("rm -rf subfinder.txt " , shell=True)
        print("")
        print("")
        print("                          ##### Sublist3r #####                                       ")
        time.sleep(3)
        print("")
        subprocess.call("sublist3r -t 4 -d " + target + " -o sublist3r.txt 2>/dev/null" ,  shell=True)
        subprocess.call("cat sublist3r.txt >> " + subdomains , shell=True)
        subprocess.call("rm -rf sublist3r.txt " , shell=True)
        print("")
        print("")
        print("                         ##### Assetfinder #####                                     ")
        time.sleep(3)
        print("")
        subprocess.call("assetfinder -subs-only " + target + " |tee assetfinder.txt 2>/dev/null", shell=True )
        #subprocess.call("assetfinder -subs-only " + target + " >> " + subdomains, shell=True )
        subprocess.call("cat assetfinder.txt >> " + subdomains , shell=True)
        subprocess.call("rm -rf assetfinder.txt " , shell=True)
        print("")
        print("")
        print("                             ##### Findomain #####                                          ")
        time.sleep(3)
        print("")
        subprocess.call("findomain -t " + target + " -u findomain.txt 2>/dev/null" ,shell=True)
        subprocess.call("cat findomain.txt >> " + subdomains , shell=True)
        subprocess.call("rm -rf findomain.txt " ,shell=True)
        print("")
        print("")
        print("                             ##### Amass #####                                          ")
        time.sleep(3)
        print("")
        subprocess.call("amass enum -passive -d " + target + " -o amass_passive.txt 2>/dev/null" , shell=True)
        subprocess.call("amass enum -active -d " + target + " -o amass_active.txt 2>/dev/null" , shell=True)
        subprocess.call("cat amass_passive.txt >> " + subdomains, shell=True)
        subprocess.call("cat amass_active.txt >> " + subdomains, shell=True)
        subprocess.call("rm -rf amass_active.txt amass_passive.txt " , shell=True)
        print("")
        print("")
        print("                          ##### Github-SubDomains #####                               ")
        time.sleep(3)
        print("")
        subprocess.call("github-subdomains -k -d " + target + " -t " + github_token, shell=True)
        subprocess.call("cat " + target +".txt >> " + subdomains, shell=True)
        subprocess.call("rm -rf " + target +".txt", shell=True)
        print("")
        print("")
        print("                               ##### Crobat #####                               ")
        time.sleep(3)
        print("")
        subprocess.call("crobat -s " + target + " |tee crobat.txt 2>/dev/null", shell=True)
        subprocess.call("cat crobat.txt >> " + subdomains, shell=True)
        subprocess.call("rm -rf crobat.txt ", shell=True)
        print("")
        print("")
        print("                                ##### Curl #####                               ")
        time.sleep(3)
        print("")
        subprocess.call("curl -s -k 'https://jldc.me/anubis/subdomains/" + target + "'" + " | grep -Po '((http|https):\/\/)?(([\w.-]*)\.([\w]*)\.([A-z]))\w+' | sed '/^\./d' |tee curl.txt 2>/dev/null", shell=True)
        subprocess.call("curl -s -k 'https://dns.bufferover.run/dns?q=." + target + "'" + " | jq -r '.FDNS_A'[],'.RDNS'[] | cut -d ',' -f2 | grep -F " + "'" + "." + target + "' |tee curl.txt 2>/dev/null", shell=True)
        subprocess.call("curl -s -k 'https://tls.bufferover.run/dns?q=." + target + "'" + " | jq -r .Results[] | cut -d ',' -f4 | grep -F " + "'" + "." + target + "' |tee curl.txt 2>/dev/null", shell=True)
        subprocess.call("cat curl.txt >> " + subdomains, shell=True)
        subprocess.call("rm -rf curl.txt ", shell=True)
        print("")
        print("")
        print("                      ##### Crtsh Subdomain Enumeration #####                        ")
        time.sleep(3)
        print("")
        subprocess.call("python3 ~/Tools/ctfr/ctfr.py -d " + target + " -o crtsh.txt", shell=True)
        subprocess.call("cat crtsh.txt >> " + subdomains, shell=True)
        subprocess.call("rm -rf crtsh.txt", shell=True)
        print("")
        print("")
        print("   #########################################################################")
        print("   #                       Start Collecting Live Subdomains                #")
        print("   #########################################################################")
        print("")
        time.sleep(5)
        subprocess.call("cat " + subdomains + " |sort -u |httprobe |tee " + resolved_subdomains, shell=True)
        print("")
        print("############################################################################")
        print("")
        subprocess.call("cat " + resolved_subdomains + " |sort -u  | cut -d / -f 3 " ,shell=True)
        subprocess.call("cat " + resolved_subdomains + " |sort -u  | cut -d / -f 3 > " + Live_subdoamins ,shell=True)
    elif Scan == "2":
        print("                            ##### Subfinder #####                                       ")
        time.sleep(3)
        print("")
        subprocess.call("subfinder -silent -d " + target + " -o subfinder.txt ", shell=True )
        subprocess.call("cat subfinder.txt > " + subdomains, shell=True)
        subprocess.call("rm -rf subfinder.txt " , shell=True)
        print("")
        print("                            ##### Sublist3r #####                                       ")
        time.sleep(3)
        print("")
        subprocess.call("sublist3r -t 4 -d " + target + " -o sublist3r.txt 2>/dev/null" ,  shell=True)
        subprocess.call("cat sublist3r.txt >> " + subdomains , shell=True)
        subprocess.call("rm -rf sublist3r.txt " , shell=True)
        print("")
        print("                            ##### Assetfinder #####                                     ")
        time.sleep(3)
        print("")
        subprocess.call("assetfinder -subs-only " + target , shell=True )
        subprocess.call("assetfinder -subs-only " + target + " >> " + subdomains, shell=True )
        print("")
        print("                             ##### Findomain #####                                          ")
        time.sleep(3)
        print("")
        subprocess.call("findomain -t " + target + " -u findomain_result.txt " ,shell=True)
        subprocess.call("cat findomain_result.txt >> " + subdomains , shell=True)
        subprocess.call("rm -rf findomain_rrsult.txt " ,shell=True)
        print("")
        print("   #########################################################################")
        print("   #                       Start Collecting Live Subdomains                #")
        print("   #########################################################################")
        print("")
        time.sleep(5)
        subprocess.call("cat " + subdomains + " |sort -u  |httprobe |tee " + resolved_subdomains, shell=True)
        print("")
        print("############################################################################")
        print("")
        subprocess.call("cat " + resolved_subdomains + " |sort -u  | cut -d / -f 3 " , shell=True)
        subprocess.call("cat " + resolved_subdomains + " |sort -u  | cut -d / -f 3 > " + Live_subdoamins ,shell=True)
    else:
        print("[-] Wrong Number!! ")
        Sub_Domains()

Sub_Domains()

#Searching for subdomain takeover

def Subdomain_TakeOver():
    print("   #########################################################################")
    print("   #                       Searching For Subdomain-TakeOver                #")
    print("   #########################################################################")
    print("")
    time.sleep(5)
    subprocess.call("mkdir Subdomain_TakeOver " , shell=True)
    os.chdir(Subdomain_TakeOver)
    print("                             ##### SubJack #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("subjack -w ../" + Live_subdoamins + " -t 100 -timeout 30 -ssl -c /root/go/src/github.com/haccer/subjack/fingerprints.json -a -v -m -o subdomain_takeover.txt", shell=True)
    print("")
    print("                             ##### SubOver #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("SubOver -l ../" + Live_subdoamins + " -a -t 100 -v -https -timeout 30 |tee subdomain_takeover_subover.txt " ,shell=True)
    subprocess.call("cat subdomain_takeover_subover.txt >> subdomain_takeover.txt " ,shell=True)
    subprocess.call("rm -rf subdomain_takeover_subover.txt " ,shell=True)
    subprocess.call("cd ../ " ,shell=True)
    print("")

 Subdomain_TakeOver()

 def Zonetransfer():
 	print("   #########################################################################")
    print("   #                         Searching For Zonetransfer                    #")
    print("   #########################################################################")
    print("")
    time.sleep(5)

Zonetransfer()

def S3bucket():
	print("   #########################################################################")
    print("   #                          Searching For S3bucket                       #")
    print("   #########################################################################")
    print("")
    time.sleep(5)

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
    print("                             ##### Waybackurls #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("cat " + Live_subdoamins + " | waybackurls | grep -v -e .css -e .jpg -e .jpeg -e .png -e .svg -e .ico |tee " + waybackurls_output ,shell=True)
    print("")
    subprocess.call("cat " + waybackurls_output + " |sort -u  |tee " + wayback , shell=True)
    subprocess.call("rm -rf " + waybackurls_output , shell=True )
    print("")
    print("                             ##### Github-Endpoints #####                                    ")
    time.sleep(3)
    print("")
    subprocess.call("python3 /usr/share/github-endpoints.py -t " + github_token + " -d " + target + " |tee endpoints.txt" ,shell=True)
    subprocess.call("cat endpoints.txt >> " + wayback ,shell=True)
    subprocess.call("rm -rf endpoints.txt " ,shell=True)
    subprocess.call("cat " + wayback + " | sort -u >> " + target + "_endpoints.txt " ,shell=True)
    subprocess.call("rm -rf " + wayback , shell=True)


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
    subprocess.call("cat " + target + "_endpoints.txt | grep '.js$' " , shell=True)
    subprocess.call("cat " + target + "_endpoints.txt | grep '.js$' >> " + jsfile , shell=True)
    subprocess.call("subfinder -d " + target + " -silent | httpx | subjs >> " + jsfile , shell=True)
    subprocess.call("gau -subs " + target + " | grep '.js$' >> " + jsfile , shell=True)
    subprocess.call("cat " + jsfile + " |sort -u >> jsfile.txt " ,shell=True)
    subprocess.call("rm -rf " + jsfile ,shell=True)

Extract_JSFiles()


#bruteforcing directories using dirsearch

#def Directory_bruteforcing():
    #print("")
    #print("")
    #print("   #########################################################################")
    #print("   #                        Start BruteForcing Directories                 #")
    #print("   #########################################################################")
    #print("")
    #time.sleep(5)
    #subprocess.call("dirsearch -l " + Live_subdoamins + " -w /usr/share/wordlists/dirb/common.txt -e php -t 4 |tee " + dir ,shell=True)

#Directory_bruteforcing()


#collect all possible vulnerable files by gf
print("")
print("")
print("   #########################################################################")
print("   #                   Start Make Possiable Vulnerable Files               #")
print("   #########################################################################")
print("")
time.sleep(5)
try:
    subprocess.call("mkdir " + vuln , shell=True)
    #print("[+] Creating " + vuln + " directory ")
    subprocess.call("cd " + vuln , shell=True)
    subprocess.call("cat " + wayback + " |grep = |gf ssrf |tee " + ssrf ,shell=True)
    subprocess.call("cat " + wayback + " |grep = |gf sqli |tee " + sqli ,shell=True)
    subprocess.call("cat " + wayback + " |grep = |gf xss |tee " + xss ,shell=True)
    subprocess.call("cat " + wayback + " |grep = |gf lfi |tee " + lfi ,shell=True)
    subprocess.call("cat " + wayback + " |grep = |gf idor |tee " + idor ,shell=True)
    subprocess.call("cat " + wayback + " |grep = |gf redirect |tee " + redirect ,shell=True)
    subprocess.call("cat " + wayback + " |grep = |gf rce |tee " + rce ,shell=True)
    subprocess.call("cd .. " ,shell=True)
    print("")

except:
    print("[-] Error has occured !")
    pass 

    
#scan vulnerability
print("")
print("")
print("   #########################################################################")
print("   #                     Start Scanning For Vulnerabilities                #")
print("   #########################################################################")
print("")
time.sleep(5)
subprocess.call("mkdir " + auto , shell=True)
#print("[+] Creating " + auto + "directory ")
subprocess.call("cd " + auto , shell=True)
try:
    subprocess.call("nuclei -l " + Live_subdoamins + " -t /usr/share/nuclei-templates/vulnerabilities/ -t /usr/share/nuclei-templates/takeovers/ -t /usr/share/nuclei-templates/dns/ -t /usr/share/nuclei-templates/cves/ -v -o subdomain_scan.txt " ,shell=True)
    subprocess.call("nuclei -l " + Live_subdoamins + " -t /usr/share/nuclei-templates/technologies/ -v -o service_info.txt " ,shell=True)
    subprocess.call("nuclei -l " + Live_subdoamins + " -t /usr/share/nuclei-templates/misconfiguration/ -v -o security_misconfigration.txt " ,shell=True)
    subprocess.call("nuclei -l jsfile.txt -t /usr/share/nuclei-templates/vulnerabilities/ -v -o tokens.txt " ,shell=True)
    subprocess.call("cd .." ,shell=True)

except:
    print("[-] Error has occured !")
    pass


#port scan
#print("")
#print("")
#print("   #########################################################################")
#print("   #                            Start Port Scanning                        #")
#print("   #########################################################################")
#print("")
#time.sleep(5)
#subprocess.call("mkdir port_scan " ,shell=True)
#print("[+] Creating port_scan directory ")
#subprocess.call("cd port_scan " ,shell=True)
#subprocess.call("naabu -iL " + Live_subdoamins + " -top-ports 1000 -o " + port , shell=True)


#bruteforce services credential

#print("   #########################################################################")
#print("   #                   Start BruteForcing Services Credentials             #")
#print("   #########################################################################")
#print("")
#subprocess.call("brutespray -f " + target_name + ".gnmap |tee credential.txt" ,shell=True)

