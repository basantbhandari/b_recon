"""
python script that do complete recon based on advanced recon methodology
ARWAD Methodology
https://ahmdhalabi.medium.com/ultimate-reconnaissance-roadmap-for-bug-bounty-hunters-pentesters-507c9a5374d
"""
import os
from urllib.parse import urlparse
import sublist3r
from nslookup_python import nslookup_python
import socket
import config
from colorama import Fore
from logger import b_logger
from logger import get_default_logger
main_logger = get_default_logger()


class b_recon():
    def __init__(self, Config):
        self.Config = Config
        self.domain_url = Config.DOMAIN_NAME
        self.output_dir = Config.OUTPUT_DIR
        self.combined_list_subdomain = []
        self.subdomain_enumeration_word_list = Config.SUBDOMAIN_ENUMERATION_WORLD_LIST
        self.domain_name = None
        self.get_domain_name()
        self.welcome_message()
        self.get_whois_information()
        self.get_DNS_information_by_dig()
        self.get_DNS_information_by_nslookup()
        self.active_sub_domain_enumeration()
        self.passive_sub_domain_enumeration()
        self.get_combined_subdomain_line_wise_not_duplicate()
        self.domain_name_to_ip()
        self.ip_to_domain_name()
        self.get_valid_domain_name()
        self.get_subdomain_takeover_possible_domains()
        self.get_live_host_ip()
        self.scan_ports_live_ip_domain()
        self.get_discovered_contents()
        self.get_sensitive_information_github()
        self.get_url_wayback_url()
        self.extract_js_files()
        self.vulnerability_scanning_nuclei()
        self.mirror_the_domain()

    @b_logger(my_logger=main_logger)
    def welcome_message(self):
        """
           function that says welcome to the user
           :return:
           """
        print(f'''{Fore.GREEN}
        ********************************************************************************
        ********************************************************************************
        ********************************************************************************
        ********************************************************************************
        *****************#@*****************************************S@******************
        ***************S%:.!&***************&%!!!!%&**************S$:.!@****************
        ***************S*....*#***********S*........*S***********@:...:$****************
        *****************&!....%#*********!..........!*********&!...:%S*****************
        *******************&!...:%S******S............S******&*....*#*******************
        *********************@:...:$*******..........******#*....*#*********************
        **********************S$:...!@*****%:......:%****S%:...!&***********************
        ************************S%....!&####@*::::*@####$:...:@*************************
        **************************#*.........::..::........:$S**************************
        ****************************&:....................!S****************************
        ******************************....................******************************
        ******************************....................******************************
        ******************************....................******************************
        ******************************....................******************************
        ******************************....................******************************
        ******************************....................******************************
        ******************************....................******************************
        ******************************....................******************************
        ******************************....................******************************
        *****************************$*.....:*%%%%*:.....*$*****************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************S.....:******:.....#******************************
        ******************************#.....:******:.....#******************************
        *******************************@@@@@@******@@@@@@S******************************
        ********************************************************************************
        ********************************************************************************
        ********************************************************************************
        ********************************************************************************
        ********************************************************************************
            ''')
        print('''

         ##   ## ####### ####      ####   #####  ##   ## #######   ######  #####  
         ##   ##  ##   #  ##      ##  ## ##   ## ### ###  ##   #   # ## # ##   ## 
         ##   ##  ## #    ##     ##      ##   ## #######  ## #       ##   ##   ## 
         ## # ##  ####    ##     ##      ##   ## #######  ####       ##   ##   ## 
         #######  ## #    ##   # ##      ##   ## ## # ##  ## #       ##   ##   ## 
         ### ###  ##   #  ##  ##  ##  ## ##   ## ##   ##  ##   #     ##   ##   ## 
         ##   ## ####### #######   ####   #####  ##   ## #######    ####   #####  

         ######            ######  #######  ####   #####  ##   ## 
          ##  ##            ##  ##  ##   # ##  ## ##   ## ###  ## 
          ##  ##            ##  ##  ## #  ##      ##   ## #### ## 
          #####             #####   ####  ##      ##   ## ## #### 
          ##  ##            ## ##   ## #  ##      ##   ## ##  ### 
          ##  ##            ##  ##  ##   # ##  ## ##   ## ##   ## 
         ######            #### ## #######  ####   #####  ##   ## 
                 ########                                         

            ''')


    @b_logger(my_logger=main_logger)
    def get_whois_information(self):
        """
        from given domain,
        I go for collecting Base information.
        WHOIS Information: Useful to check information about domain owners
        (gather emails, phone numbers) and registration details.

        :param domain:
        :return:
        """
        try:
            output_file_path = self.output_dir + f'base_information/{self.domain_name}_whose_is_information.txt'
            os.system(f"whois {self.domain_name} | cat > {output_file_path}")
            return True
        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def get_DNS_information_by_nslookup(self):
        """
        DNS Information: Very useful to understand the domain logistics
        and start predicting what vulnerabilities related to DNS you can look for.
        tools: dnsenum, dnsmap, gobuster, atk6-dnsdict6

        :param domain:
        :return:
        """
        try:
            if self.domain_name:
                output_file_path = self.output_dir + f'base_information/{self.domain_name}_nslookup_info.txt'
                nslookup_python1 = nslookup_python(types=["A", "NS", "TXT", "CNAME", "AAAA", "MX", "ALIAS",
                                                          "PTR", "SRV"], url=self.domain_name)
                all_information = nslookup_python1.run()
                f = open(output_file_path, "a")
                for item in all_information:
                    f.write(item)
                f.close()
                return True
            else:
                return False
        except Exception as e:
            return False


    @b_logger(my_logger=main_logger)
    def get_DNS_information_by_dig(self):
        """
        DNS Information: Very useful to understand the domain logistics
        and start predicting what vulnerabilities related to DNS you can look for.
        tools: dnsenum, dnsmap, gobuster, atk6-dnsdict6

        :param domain:
        :return:
        """
        try:
            if self.domain_name:
                output_file_path = self.output_dir + f'base_information/{self.domain_name}_dig_info.txt'
                os.system(f"dig {self.domain_name} | cat > {output_file_path}")
                return True
            else:
                return False
        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def get_acquisitions(self):
        """
        Acquisitions: Looking for companies acquired by the target domain will in order give you more domains
        to target high chances to find more vulnerabilities.

        :param domain:
        :return:
        """
        # more manual task
        # TODO do manually by  searching
        pass


    @b_logger(my_logger=main_logger)
    def mirror_the_domain(self):
        """
        it copy the website available online in local

        :param domain_url:
        :return:
        """
        try:
            os.system(f'wget -m {self.domain_url}')
            return True
        except Exception as e:
            return False


    @b_logger(my_logger=main_logger)
    def get_domain_url(self):
        """
        take the one domain url from the user
        :return:
        """
        try:
            self.domain_url = input("Enter domain url: ")
            return True
        except Exception as e:
            return False


    @b_logger(my_logger=main_logger)
    def get_domain_name(self):
        """
        convert the current domain url into domain name
        :return:
        """
        try:
            if self.domain_url:
                self.domain_name = urlparse(self.domain_url).netloc.replace("www.", '')
                return True
            else:
                return False
        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def get_domain_name_www(self):
        """
        convert the current domain url into domain name
        :return:
        """
        try:
            if self.domain_url:
                self.domain_name = urlparse(self.domain_url).netloc
                return True
            else:
                return False
        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def active_sub_domain_enumeration(self):
        """
        find all the sub domain for the root domain
        use amass
        :return:
        """
        try:
            if self.domain_name:
                output_file_path = self.output_dir + f'sub_domain_enumeration/{self.domain_name}_amass.txt'
                os.system(f'amass enum -brute -d {self.domain_name} -src -w {self.subdomain_enumeration_word_list} | '
                          f'cut -b 19- > {output_file_path}')
                # for cleaned domain
                output_file_path_cleaned = self.output_dir + f'sub_domain_enumeration/{self.domain_name}_amass_cleaned.txt'
                os.system(f"cat {output_file_path} | cut -b 19- > {output_file_path_cleaned}")
                self.combined_list_subdomain.append(output_file_path_cleaned)
                return True
        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def passive_sub_domain_enumeration(self):
        """
        find all the sub domain for the main domain
        use sublist3r
        :return:
        """
        try:
            output_file_path = self.output_dir + f'sub_domain_enumeration/{self.domain_name}_sublister.txt'
            sublist3r.main(self.domain_name, 40, output_file_path, ports= None, silent=False, verbose= False,
                           enable_bruteforce= False, engines=None)
            self.combined_list_subdomain.append(output_file_path)
            return True
        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def get_combined_subdomain_line_wise_not_duplicate(self):
        """
        it combine the multiple files line wise so that no duplicate line
        :return:
        """
        output_file_path = self.output_dir + f'sub_domain_enumeration/{self.domain_name}_combined_subdomain_no_duplication.txt'
        all_lines = []
        if bool(self.combined_list_subdomain):
            for item in self.combined_list_subdomain:
                with open(item, 'r') as fi:
                    all_lines += fi.readlines()
                fi.close()
        all_lines = set(all_lines)
        with open(output_file_path, 'w') as fo:
            fo.write("".join(all_lines))
        fo.close()

    @b_logger(my_logger=main_logger)
    def http_appender_domain_name(self):
        """
        given name we have example.com
        make this like: http://www.example.com
        :return:
        """
        all_new_lines = []
        if self.source_data_path and self.destination_data_path:
            with open(self.source_data_path, "r") as fs:
                all_lines = fs.readlines()
            fs.close()

            for each_line in all_lines:
                new_each_line = "http://www." + str(each_line)
                all_new_lines += new_each_line

            with open(self.destination_data_path, 'w') as fs:
                fs.writelines(all_new_lines)
            fs.close()
        return True

    @b_logger(my_logger=main_logger)
    def https_appender_domain_name(self):
        """
        given name we have example.com
        make this like: https://www.example.com
        :return:
        """
        all_new_lines = []
        if self.source_data_path and self.destination_data_path:
            fs = open(self.source_data_path, "r")
            all_lines = fs.readlines()
            fs.close()

            for each_line in all_lines:
                new_each_line = "https://www." + str(each_line)
                all_new_lines += new_each_line

            fs = open(self.destination_data_path, 'w')
            fs.writelines(all_new_lines)
            fs.close()
        return True

    @b_logger(my_logger=main_logger)
    def domain_name_to_ip(self):
        """
        example.com
        convert this to
        192.168.0.10

        :return:
        """
        source_data_path = f"output/sub_domain_enumeration/{self.domain_name}_combined_subdomain_no_duplication.txt"
        destination_data_path = f"output/sub_domain_enumeration/{self.domain_name}_final_ip_all.txt"
        fs = open(source_data_path, "r")
        all_lines = fs.readlines()
        fs.close()
        all_new_lines = ""
        for each_line in all_lines:
            new_each_line = socket.gethostbyname(each_line.strip())
            all_new_lines += new_each_line + "\n"
        fs = open(destination_data_path, 'w')
        fs.writelines("".join(all_new_lines))
        fs.close()
        return True

    @b_logger(my_logger=main_logger)
    def ip_to_domain_name(self):
        """
        192.168.0.10
        convert this to
        example.com

        :return:
        """
        all_new_lines = []
        source_data_path = f"output/sub_domain_enumeration/{self.domain_name}_final_ip_all.txt"
        destination_data_path = f"output/sub_domain_enumeration/{self.domain_name}_final_domain_name_all.txt"
        fs = open(source_data_path, "r")
        all_lines = fs.readlines()
        fs.close()
        for each_line in all_lines:
            try:
                new_each_line = socket.gethostbyaddr(each_line[:-1])
                all_new_lines += new_each_line[0] +"\n"
            except Exception as e:
                continue
        fs = open(destination_data_path, 'w')
        fs.writelines(all_new_lines)
        fs.close()
        return True

    @b_logger(my_logger=main_logger)
    def get_valid_domain_name(self):
        """
        it gives the url that give the response back with valid url
        use the httpx tools to get the valid url from the domain name
        steps:
        make the domain name with https://www.
        make the domain name with http://www.
        :return:
        """
        output_file_path = self.output_dir + f'sub_domain_enumeration/{self.domain_name}_combined_subdomain_valid.txt'
        source_data_path = self.output_dir + f'sub_domain_enumeration/{self.domain_name}_combined_subdomain_no_duplication.txt'
        destination_data_path = f'.temp/{self.domain_name}_full_domain.txt'

        self.http_appender_domain_name()
        fs = open(destination_data_path, 'r')
        http_domain_name = fs.readlines()
        fs.close()

        self.https_appender_domain_name()
        fs = open(destination_data_path, 'r')
        https_domain_name = fs.readlines()
        fs.close()

        total_url = []
        total_url.append(http_domain_name)
        total_url.append(https_domain_name)

        total_url_string = ""
        for item in total_url:
            for i in item:
                total_url_string += i

        temp_combined_http_https_domain_name = f'.temp/{self.domain_name}_temp_combined_http_https_domain_name.txt'
        fs = open(temp_combined_http_https_domain_name, 'w')
        fs.write(total_url_string)
        fs.close()
        command = f"cat {temp_combined_http_https_domain_name} | httpx -probe | grep SUCCESS | cut -d ' ' " \
                  f"-f 1 > {output_file_path}"
        os.system(command)

        return True

    @b_logger(my_logger=main_logger)
    def get_subdomain_takeover_possible_domains(self):
        """
        using subjack and tko-subs, it is sub domain takeover vulnerability scanner
        :return:
        """
        try:
            figure_print_file = self.Config.SUB_JECK_FINGUREPRINT
            input_data_file_path = f"./output/sub_domain_enumeration/{self.domain_name}_combined_subdomain_no_duplication.txt"
            output_data_file_path = f"./output/sub_domain_enumeration/{self.domain_name}_subdomain_takeover_vulnerability.txt"
            command = f'subjack -w {input_data_file_path} -c {figure_print_file} -t 100 -timeout 30 ' \
                      f'-o {output_data_file_path} -ssl'
            os.system(command)
            return True
        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def get_live_host_ip(self):
        f"""
        takes the list of ip and an saves the results.
        :return:
        """
        try:
            source_data_path = f"output/sub_domain_enumeration/{self.domain_name}_combined_subdomain_no_duplication.txt"
            destination_data_path = f"output/sub_domain_enumeration/{self.domain_name}_live_subdomains_fping.txt"
            payloads_ips = ""
            fs = open(source_data_path, 'r')
            all_lines = fs.readlines()
            fs.close()
            for each_ip in all_lines:
                payloads_ips += each_ip.strip()+' '

            command = f'fping {payloads_ips}| grep alive | cut -d " " -f 1 > {destination_data_path}'
            os.system(command)
            return True

        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def scan_ports_live_ip_domain(self):
        """
        it reads the live domain and check its defaults ports along with service and their version information
        :return:
        """
        try:
            source_data_path = f"output/sub_domain_enumeration/{self.domain_name}_combined_subdomain_no_duplication.txt"
            destination_data_path = f"output/sub_domain_enumeration/{self.domain_name}_port_scanning_service_version.txt"
            fs = open(source_data_path, 'r')
            all_lines = fs.readlines()
            fs.close()
            temp_each_scanner_output = f'.temp/{self.domain_name}_each_port_scanning_service_version_temp.txt'
            for each_ip in all_lines:
                fo = open(destination_data_path, 'a')
                command = f'nmap -sV --script vulners.nse {each_ip.strip()} > {temp_each_scanner_output}'
                os.system(command)
                fs1 = open(temp_each_scanner_output, 'r')
                data_info = fs1.readlines()
                fs1.close()
                fo.writelines(data_info)
                fo.close()
                return True
        except Exception as e:
            return False


    @b_logger(my_logger=main_logger)
    def get_discovered_contents(self):
        """
        after collecting all live domain
        collect more content about that domains
        fuzzing
        directory search disearch
        directory bruite-force ffuf
        seclist
        https://www.linkedin.com/pulse/bug-bounty-content-discovery-jamie-shaw/

        here, iam using four tools for content discovery
        wfuzz
        ffuf
        gobuster
        feroxbuster
        :return:
        """
        try:
            if self.domain_url and self.domain_name:
                # read all the live domain from host
                command = f'feroxbuster -u {self.domain_url} -x pdf -x js,html -x php txt json,docx -w ' \
                          f'/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -o ' \
                          f'{self.output_dir}sub_domain_enumeration/content_discovery/result_feroxbuster.txt'
                os.system(command)
                command = f'gobuster dns -d {self.domain_name} -w /opt/SecLists/Discovery/Web-Content/' \
                          f'raft-medium-directories.txt -o {self.output_dir}sub_domain_enumeration/' \
                          f'content_discovery/result_gobuster.txt'
                os.system(command)
                command = f'wfuzz -c -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u ' \
                          f'{self.domain_url}FUZZ > {self.output_dir}sub_domain_enumeration/content_discovery/' \
                          f'result_wfuzz.txt'
                os.system(command)
                command = f'ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt -u ' \
                          f'{self.domain_url}FUZZ > {self.output_dir}sub_domain_enumeration/' \
                          f'content_discovery/result_ffuf.txt'
                os.system(command)

                return True

        except Exception as e:
            return False


    @b_logger(my_logger=main_logger)
    def get_sensitive_information_github(self):
        """
        after collecting all live domain
        collect more content about that domains
        automation GitHound
        manual searching
        :return:
        """
        try:
            source_data_path = f"./output/sub_domain_enumeration/{self.domain_name}_full_domain.txt"
            destination_data_path = f"./output/sub_domain_enumeration/secret_info/{self.domain_name}_secret_info.txt"
            # read all the live domain from host
            command = f'echo "\"{self.domain_name}\"" | git-hound --subdomain-file {source_data_path} ' \
                      f'| tee {destination_data_path}'
            os.system(command)
            return True

        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def get_url_wayback_url(self):
        """
        after collecting all live domain
        collect more content about that domains
        gau,
        possible vulnerable links GF-patterns
        extensions grep (php, aspx)
        :return:
        """
        try:
            source_data_path = f"./output/sub_domain_enumeration/{self.domain_name}_full_domain.txt"
            if source_data_path:
                # read all the live domain from host
                command = f'cat {source_data_path} | gau --o ./output/sub_domain_enumeration/past_data/{self.domain_name}_result_gau.txt --threads 5'
                os.system(command)
                # https://github.com/tomnomnom/waybackurls
                command = f'cat {source_data_path} | waybackurls > ./output/sub_domain_enumeration/past_data/{self.domain_name}_result_waybackurls.txt'
                os.system(command)
                return True

        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def extract_js_files(self):
        """
        after collecting all live domain
        collect more content about that domains
        extract js file
        extract URLs/endpoint
        analysis of js file,
        searching for APIs, credentials,
        endpoints, subdomains.
        :return:
        """
        try:
            # using linkfinder
            command = f'python /home/basant/Downloads/userapp/LinkFinder/linkfinder.py {self.domain_url} -o ' \
                      f'./output/sub_domain_enumeration/extracted_js_file/{self.domain_name}_result_linkfinder.txt'
            os.system(command)
            # using golinkfinder
            command = f'GoLinkFinder {self.domain_url} -o ./output/sub_domain_enumeration/extracted_js_file/{self.domain_name}_result_golinkfinder.txt'
            os.system(command)
            return True

        except Exception as e:
            return False

    @b_logger(my_logger=main_logger)
    def vulnerability_scanning_nuclei(self):
        """
        after collecting all live domain
        collect more content about that domains
        nuclei,
        possible vulnerable links
        GF patterns
        :return:
        """
        try:
            source_data_path = f"./output/sub_domain_enumeration/{self.domain_name}_full_domain.txt"
            destination_data_path = f"./output/sub_domain_enumeration/nuclei_results/{self.domain_name}_nuclei_scanning_results.txt"
            if source_data_path and destination_data_path:
                command = f'nuclei -list {source_data_path} -o {destination_data_path}'
                os.system(command)
                return True

        except Exception as e:
            return False


if __name__ == '__main__':
    b_recon1 = b_recon(config.Config)

