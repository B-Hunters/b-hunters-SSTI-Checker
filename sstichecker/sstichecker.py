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
from bson.objectid import ObjectId

def runsstichecker(url):
    result=""
    output=""
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
                    return result,output

            except requests.exceptions.RequestException:
                pass

    except Exception as e:
        print("error ",e)
        # result=[]
    return ""

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
            data=self.backend.download_object("bhunters",f"{source}_"+self.scanid+"_"+self.encode_filename(url))
        except Exception as e:
            raise Exception(e)


        filename=self.generate_random_filename()+".txt"
        with open(filename, 'wb') as file:
            # for item in data:
            file.write(data)

        p1 = subprocess.Popen(["cat", filename], stdout=subprocess.PIPE)
        p3 = subprocess.Popen(["grep", "-v", "png\|jpg\|css\|js\|gif\|txt"], stdin=p1.stdout, stdout=subprocess.PIPE)
        p1.stdout.close()
        # Command 4: grep '='
        p4 = subprocess.Popen(["grep", "="], stdin=p3.stdout, stdout=subprocess.PIPE)
        p3.stdout.close()

        # Command 5: uro
        p5 = subprocess.Popen(["uro","--filter","hasparams"], stdin=p4.stdout, stdout=subprocess.PIPE)
        p4.stdout.close()
        p6 = subprocess.Popen(["qsreplace","FUZZ"], stdin=p5.stdout, stdout=subprocess.PIPE)
        p5.stdout.close()
        data2=self.checklinksexist(self.subdomain,p6.stdout.read().decode("utf-8"))
        # URL encode each entry in data2
        dataencoded = [url.replace(' ', '%20') for url in data2 if url]
        p6.stdout.close()

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
                        self.log.info(f"Vulnerability found at {res[0]}")
                        self.log.info(res[1])

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
        self.scanid=task.payload_persistent["scan_id"]
        report_id=task.payload_persistent["report_id"]
        self.update_task_status(subdomain,"Started")
        self.log.info("Starting processing new url")
        self.log.warning(f"{source} {url}")
        try:
                
            result=self.scan(url,source)
            self.waitformongo()
            db=self.db
            collection=db["reports"]
            if result !=None and result !=[]:
                domain_document = collection.find_one({"_id": ObjectId(report_id)})
                if domain_document:
                    collection.update_one({"_id": report_id}, {"$push": {f"Vulns.SSTIMap": {"$each": result}}})
                resultarr=[]
                for i in result:
                    resultarr.append(i[0])
                output="\n".join(resultarr)

                self.send_discord_webhook("SSTI Checker",output,"main")
        except Exception as e:
            self.log.error(e)
            self.update_task_status(subdomain,"Failed")
            raise Exception(e)
        self.update_task_status(subdomain,"Finished")
