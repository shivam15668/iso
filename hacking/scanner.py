import os 
import re
import ssl
import subprocess
import asyncio
import json
from OpenSSL import crypto
import aiohttp #module to make concurrent request
#from cryptography import x509 # if we work with commented cert_thread
#from cryptography.hazmat.backends import default_backend
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup, SoupStrainer
class SSLChecker:

    
    def __init__(self, ssl_port= 443, MAX_CONCURRENT = 100, mass_scan_results_file="masscanResults.txt", ips_file= "ips.txt",masscan_rate = 10000 , chunkSize= 2000 ,timeout =2 ,semaphore_limit = 70 , protocols = ["http://", "https://"]):  
        self.ssl_port = ssl_port
        self.timeout = timeout
        self.chunkSize = chunkSize
        self.mass_scan_results_file= mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate
        self.protocols = protocols
        self.MAX_CONCURRENT = MAX_CONCURRENT
        self.semaphore_limit = asyncio.Semaphore(semaphore_limit)
    
    def is_valid_domain(self,common_name):
         domain_pattern = r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
         return re.match(domain_pattern,common_name) is not None
    
    async def makeGetRequestToDomain(self,session,ip,protocol,common_name,makeGetRequestByIP=True):
        async def parseResponse(url,port):
            try:
                if self.semaphore.locked():
                    await asyncio.sleep(1)
                redirected_domain = ""
                response_headers = {}
                first_300_words = ""
                title= ""
                
                async with session.get(url,allow_redirects=True, timeout = self.timeout,ssl = False) as res:
                    # we want to allow rediects to happen # we will make http request so we dont use ssl certificated all the time
                    response = await res.text(encoding = "utf-8")
                    content_type  = res.headers.get("Content-Type")
                    ""
                    if res.headers is not None:
                        for key,value in res.headers.items():
                            response_headers[key] = value.encode("utf-8","surrogatepass").decode("utf-8")# if on the way to encoding , come across special , ignore them and decode(rest) them as they are
                    
                    if res.history:
                        redirected_domain = str(res.url) #to get redirected url
                    
                    #parsing our data
                    
                    if response is not None and content_type is not None:
                        if "xml" in content_type:
                            root = ET.fromstring(response)
                            # if content_type we get from target is xml , ET.fromstring will help us to get xml values
                            # we get xml root
                            xmlwords = []
                            count = 0 
                            
                            for elem in root.iter():
                                if elem.text:
                                    xmlwords.extend(elem.text.split())
                                    count+= len(xmlwords)
                                if count >= 300:
                                    break
                            if xmlwords:
                                first_300_words = " ".join(xmlwords[:300]) #join list by space
                                # xmlwords = ["adam","jhon"]
                                # adam john
                            elif"html" in content_type:
                                # we have multiple content_type that we can recieve from target
                                strainer = SoupStrainer(["title","body"])
                                #soupstrainer is faster to extract content from html 
                                soup = BeautifulSoup(response,"html.parser",parse_only = strainer)
                                title_tag = soup.title
                                body_tag = soup.body
                                
                                if title_tag and title_tag.string:
                                    title = title_tag.string.strip() # strip removes spaces at beginning or end of strings
                                
                                if body_tag:
                                    body_text = body_tag.get_text(separator = " " , strip = True)
                                    words = body_text.split() # we get x amount of word from body
                                    # hello how are you  -> ["hello", "how", "are", "you"] -> words[:2]
                                    first_300_words = " ".join(words[:300])
                                
                                if not body_tag or not title_tag:
                                    words = response.split()
                                    first_300_words = " ".join(words[:300])
                                
                            elif "plain" in content_type:
                                words = response.split()
                                first_300_words = " ".join(words[:300])
                                    
                            elif "json" in content_type:
                                 first_300_words = response[:300]
                                 
                            if makeGetRequestByIP:
                                print(f"Title: {title} , {protocol}{ip}:{port}")
                            else:
                                print(f"Title: {title}, {protocol}{common_name}:{port}")
                                
                            
            
            except Exception as e:
                pass
    
    
    async def check_site(self,session,ip,common_name):
        try:
         #semaphore to limit amount of requests
            async with self.semaphore:  #run whatever we have inside semaphore 70 times in parallel maximum  
                temp_dict = {}
                if "*" in common_name or not self.is_valid_domain(common_name):
                  for protocol in self.protocols: # we have 2 protocols to deal with http, https
                     dict_res = await self.makeGetRequestToDomain(session, protocol,ip,common_name, True)
                     temp_dict[f'{protocol.replace("://","")}_responseForIP'] = dict_res
                     # we will have http_responseForIP
                     """
                     {
                        http_responseForIP:{
                            name:"adam"
                        },
                         https_responseForIP:{
                             name:"adam"
                          }
                        
                     }
                    """
                   # so if the common name isnot yahoo.com and just yahoo or *yahoo.com then you are going to make request using IP address , 2 request , one on http and one on https
                   # http://122.22.33.44
                   # https://122.23.23.44
                   # if you dont have a domain name
                   # just make 2 request using ip
                   # we pass true so as to make request in special names
                else:
                    for protocol in self.protocols:
                       
                       dict_res = await self.makeGetRequestToDomain(session,protocol,ip,common_name,False)
                       temp_dict[f'{protocol.replace("://","")}_responseForDomainName'] = dict_res
                       # if we have valid domain , make request using domain name and ip address to get max info
                    for protocol in self.protocols:
                       
                       dict_res = await self.makeGetRequestToDomain(session,protocol,ip,common_name,True)
                       temp_dict[f'{protocol.replace("://","")}_responseForIP'] = dict_res # 2 values http_requestForIP and https_requestForIp
                    temp_dict = {k: v for k,v in temp_dict.items() if v is not None}
                    if temp_dict:
                        return temp_dict
                    
        except Exception as e:
            print("Error for ",ip,":",e)
        return None
    
    
    
    
    
    async def fetch_certificate(self,ip):
        try:
            cert  = await  asyncio.to_thread(ssl.get_server_certificate(ip,self.ssl_port),timeout = self.timeout)
            x509=crypto.load_certificate(crypto.FILETYPE_PEM,cert)#base 64 encoding to store binary data 
            # to_thread uses multiple available thread of cpu
            # await means this part of code waits on to coomplete server_certificate first , for this context only 
            # ssl.get_server_certificate is synchronous by default
            # crypto will manipulate x509 certificates
            # we need info from cert get_subject() 
            subject= x509.get_subject()
            common_name = subject.CN
            print(common_name)
            
            #if upper part doesn't work use this 
            # cert_data = await asyncio.to_thread(ssl.get_server_certificate ,(ip,443), ssl_version= ssl.PROTOCOL_TLS)
            # x509_cert = x509.load_pem_x509_certificate(cert_data.encode() , default_backend())
            # common_name = x509_cert.subject.get_attribute_for_oid(x509.NameOID.COMMON_NAME)[0].value
            return ip,common_name # think of common name as domain name could be like *name
        except Exception as e:
            print(f"Error for {ip}: {e}")
        return ip,"" #return tuple of ip and empty string if common name not found
    
    
    
    
    
    async def extract_domains(self): #self is commented out , check for this in later version
        #try:
            with open(self.mass_scan_results_file,"r") as file:
                content=file.read()
            
            ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            ip_addresses = re.findall(ip_pattern,content)
            
            for i in range(0,len(ip_addresses),self.chunkSize):
              async with aiohttp.ClientSession(connector = aiohttp.TCPConnector(limit= self.MAX_CONCURRENT,ssl = False)) as session: #create a seesion for me to make request
                 chunk_of_IPs = ip_addresses[i:i+self.chunkSize]
                 ip_and_common_names = []
                
                 ip_and_common_names = await asyncio.gather(*[self.fetch_certificate(ip) for ip in chunk_of_IPs])  #look chunk of IPs and fetch certificate
                #response of fetch_cert is waiting in IO buffer and post it to ip_and_common_name
                #ayncio uses single thread at a time
                # thats why it is so fast, takes what to run and then run
                # much like event loop in node js , doesn't wait for target server to respond , just runs the next one
                # runs one single thread, and deals with multiple calls, function using a single thread
                # asyncio.gather uses only one thread
                 allResponses = await asyncio.gather(*[self.check_sites(session,ip,common_name)for ip,common_name in ip_and_common_names]) # create fuunction check_site and giving ip and common_name to gather info
  
  
  
  
    def run_masscan(self):
        try:
            command = f"sudo masscan -p443 --rate {self.masscan_rate}  --wait 0 -iL {self.ips_file} -oH  {self.mass_scan_results_file}"
            subprocess.run(command,shell=True, check = True)
        except subprocess.CalledProcessError as e:
            print(f"Error while running masscan: {e}")
        except FileNotFoundError:
            print("Masscan executable not found")
        except Exception as e:
            print(f"An unexpected error occured: {e}")
    
    
    
    def check_and_create_files(self,*file_paths):
        for file_path in file_paths:
            if not os.path.exists(file_path):
                with open(file_path, "w") as file:
                    pass
                print(f'file "{file_path}"has been created')
        
        
        
        
        
    async def main(self):        
        self.check_and_create_files(self.mass_scan_results_file,self.ips_file)
        self.run_masscan()
        await self.extract_domains()





if __name__ == "__main__":
    ssl_checker = SSLChecker()
    asyncio.run(ssl_checker.main())
    # purpose is to create a new event loop for duration of call and close after function is completed