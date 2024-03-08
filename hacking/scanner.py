import os 
import re
import subprocess
import asyncio
import aiohttp #module to make concurrent request 
class SSLChecker:

    
    def __init__(self, ssl_port= 443,  mass_scan_results_file="masscanResults.txt", ips_file= "ips.txt",masscan_rate = 10000 , chunkSize= 2000 ,timeout =2  ):  
        self.ssl_port = ssl_port
        self.timeout = timeout
        self.chunkSize = chunkSize
        self.mass_scan_results_file= mass_scan_results_file
        self.ips_file = ips_file
        self.masscan_rate = masscan_rate
        
    async def extract_domains():
        #try:
            with open(self.mass_scan_results_file,"r") as file:
                content=file.read()
            
            ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            ip_addresses = re.findall(ip_pattern,content)
            
            for i in range(0,len(ip_addresses),self.chunkSize):
             async with aiohttp.ClientSession(connector = aiohttp.TCPConnector(limit= self.MAX_CONCURRENT,ssl = False)) as session: #create a seesion for me to make request
                chunk_of_IPs = ip_addresses[i:i+self.chunkSize]
                ip_and_common_names = []
                
  
  
  
  
  
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
        
        
        
        
        
    def main(self):
        self.check_and_create_files(self.mass_scan_results_file,self.ips_file)
        self.run_masscan()
        await self.extract_domains()





if __name__ == "__main__":
    ssl_checker = SSLChecker()
    ssl_checker.main()