from .__version__ import __version__
import subprocess
import json
import os
from urllib.parse import urlparse
from b_hunters.bhunter import BHunters
from karton.core import Task
import shutil
import re
import multiprocessing
import warnings
import requests
import requests.exceptions

def runsstichecker(url):
    result=""
    try:
        # for i in data:
        if url != "":
            try:
                # Disable certificate verification with verify=False
                requests.get(url, verify=False,timeout=5)
                p1 = subprocess.Popen(["python3","/root/SSTImap/sstimap.py","-u",url], stdout=subprocess.PIPE)
            
                try:
                    output, _ = p1.communicate(timeout=int(os.getenv("process_timeout","600")))  # 10 minutes timeout
                except subprocess.TimeoutExpired:
                    p1.kill()
                    output, _ = p1.communicate()
                    return result
                output=output.decode('utf-8')
                if "appear to be not injectable" not in output:
                    result=url

            except requests.exceptions.RequestException:
                pass

    except Exception as e:
        print("error ",e)
        # result=[]
    return result

class sstichecker(BHunters):
    """
    B-Hunters SSTI checker developed by Bormaa
    """

    identity = "B-Hunters-SSTI-Checker"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "paths", "stage": "scan"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
               
    def scan(self,url,source):
        try:    
            data=self.backend.download_object("bhunters",f"{source}_"+self.encode_filename(url))
        except Exception as e:
            raise Exception(e)


        filename=self.generate_random_filename()+".txt"
        with open(filename, 'wb') as file:
            # for item in data:
            file.write(data)

        p1 = subprocess.Popen(["cat", filename], stdout=subprocess.PIPE)
        p2 = subprocess.Popen(["grep","="], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()

        p3 = subprocess.Popen(["uro","--filter","hasparams"], stdin=p2.stdout, stdout=subprocess.PIPE)
        p2.stdout.close()
        p4 = subprocess.Popen(["qsreplace","-a"], stdin=p3.stdout, stdout=subprocess.PIPE)
        p3.stdout.close()
        data2=self.checklinksexist(self.subdomain,p4.stdout.read().decode("utf-8"))
        # URL encode each entry in data2
        dataencoded = [url.replace(' ', '%20') for url in data2 if url]
        
        result=[]
        try:
            if data2 != ['']:
                pool = multiprocessing.Pool(processes=int(os.getenv("process_num","15")))
                result_array = pool.map(runsstichecker, dataencoded)
                pool.close()
                pool.join()
                for res in result_array:
                    if res !="":
                        result.append(res)

            # result=runsstichecker(data2)
        except Exception as e:
            self.log.error(e)
            raise Exception(e)
        os.remove(filename)
        return result
        
        
    def process(self, task: Task) -> None:
        url = task.payload["data"]
        subdomain=task.payload["subdomain"]
        self.subdomain=subdomain
        source=task.payload["source"]
        self.update_task_status(subdomain,"Started")
        self.log.info("Starting processing new url")
        self.log.warning(f"{source} {url}")
        try:
                
            result=self.scan(url,source)
            db=self.db
            collection=db["domains"]
            if result !=None and result !=[]:
                domain_document = collection.find_one({"Domain": subdomain})
                if domain_document:
                    collection.update_one({"Domain": subdomain}, {"$push": {f"Vulns.SSTIMap": {"$each": result}}})
                self.send_discord_webhook("SSTI Checker","\n".join(result),"main")
        except Exception as e:
            self.log.error(e)
            self.update_task_status(subdomain,"Failed")
            raise Exception(e)
        self.update_task_status(subdomain,"Finished")