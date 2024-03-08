import os 
import re
import ssl
import subprocess
import asyncio
from OpenSSL import crypto
import aiohttp #module to make concurrent request 
class SSLChecker:

    
    def __init__(self, ssl_port= 443, MAX_CONCURRENT = 100, mass_scan_results_file="masscanResults.txt", ips_file= "ips.txt",masscan_rate = 10000 , chunkSize= 2000 ,timeout =2  ):  
        self.ssl_port = ssl_port
        self.timeout = timeout
        self.chunkSize = chunkSize
        self.mass_scan_results_file= mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate
        self.MAX_CONCURRENT = MAX_CONCURRENT
    
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
    ssl_checker.main()