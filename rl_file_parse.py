import argparse
import json

checkMalware = False
checkSuspect = False
vulnExists = True
vulnThreshold=0
behaviors=[]
vulns = []
findings={}
files=[]

def process_config(json_file):
    global checkMalware, checkSuspect, vulnExists, vulnThreshold, behaviors, findings
    try:
        data = json_file
        findings["config"]=data
        findings["findings"]=[]
        print(f"Successfully loaded Config data")
        
        checkMalware = data["malware"]
        checkSuspect = data["suspect"]
        vulnExists=data["vulnExists"]
        vulnThreshold=data["vulnThreshold"]
        behaviors=data["behaviors"]

    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Config file")
    except Exception as e:
        print(f"An error occurred while processing Config JSON: {str(e)}")



def process_vulns(report_file, vuln_file):
    global findings
    try:
        data = report_file
        print(f"Successfully loaded the Report data")
        vuln = vuln_file
        print(f"Successfully loaded the Vulns data")

        numVuln=data["report"]["metadata"]["assessments"]["vulnerabilities"]["count"]
        if numVuln == 0:
            print("No vulnerabilities detected!")
        else:
            print("Vulnerabilities detected!")
            for item in vuln:
                temp = {}
                if item["cve_score"] > vulnThreshold and item["detections"]:
                    temp["type"]="vulnerability"
                    temp["name"]=item["cve_name"]
                    temp["severity"] = item["cve_score"]
                    temp["description"] = item["description"]
                    temp["locations"]=item["detections"]
                    findings["findings"].append(temp)
                elif vulnExists and "YES" in item["exploitable"] and item["detections"]:
                    temp["type"]="vulnerability"
                    temp["name"]=item["cve_name"]
                    temp["severity"] = item["cve_score"]
                    temp["description"] = item["description"]
                    temp["locations"]=item["detections"]
                    findings["findings"].append(temp)

        print("Done processing vulns!")
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Report file")
    except Exception as e:
        print(f"An error occurred while processing Report JSON: {str(e)}")



def process_malware(report_file, malware_file):
    global findings

    try:
        data = report_file
        print(f"Successfully loaded the Report data")
        mal = malware_file
        print(f"Successfully loaded the Malware data")
    
        ##Check for Malware
        if checkMalware:
            print("Checking for Malware....")
            numMal=data["report"]["metadata"]["assessments"]["malware"]["count"]
            if numMal == 0:
                print("No malware detected!")
            else:
                print("Malware Detected!")
                
                for item in mal:
                    temp = {}
                    if item["malware_name"] and not item["suspected_malware"]: ## Check if malware is TRUE
                        temp["type"]="malware"
                        temp["name"]=item["malware_name"]
                        temp["suspect"] = False
                        temp["locations"]=item["detections"]
                        findings["findings"].append(temp)
                    elif  checkSuspect and  item["suspected_malware"]: ## Check if config has suspect set to TRUE
                        temp["type"]="suspected malware"
                        temp["name"]=item["malware_name"]
                        temp["suspect"] = True
                        temp["locations"]=item["detections"]
                        findings["findings"].append(temp)
        else:
            print("Not checking for malware...")

    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in the Report file")
    except Exception as e:
        print(f"An error occurred while processing Report JSON: {str(e)}")


def process_behaviors(report_file, behavior_file):
    global behaviors

    if len(behaviors) > 0:
        for behavior in behaviors:
            temp = {}
            search = next((item for item in behavior_file if item["bhcode"] == behavior), None)

            if search is not None:
                temp["type"] = "behavior"
                temp["name"] = behavior
                temp["description"] = search["behavior"] + " => " + search["explaination"]
                temp["locations"] = search["detections"]
                findings["findings"].append(temp)
    else:
        return {}
    

def get_all_file():
    global findings
    global files 

    for items in findings["findings"]:
        temp = items["locations"]

        for loc in temp:
            files.append(loc)
    
    findings["files"] = files




def main():
    parser = argparse.ArgumentParser(description="Process needed files")
    parser.add_argument('-r', '--report', type=argparse.FileType('r'), required=True, help="Input Report JSON file")
    parser.add_argument('-c', '--config', type=argparse.FileType('r'), required=True, help="Input Config JSON file")
    parser.add_argument('-v', '--vulns', type=argparse.FileType('r'), required=True, help="Input CVE JSON file")
    parser.add_argument('-m', '--malware', type=argparse.FileType('r'), required=True, help="Input Malware JSON file")
    parser.add_argument('-b', '--behavior', type=argparse.FileType('r'), required=True, help="Input Malware JSON file")
    args = parser.parse_args()

    configContent = json.load(args.config)
    reportContent = json.load(args.report)
    vulnsContent = json.load(args.vulns)
    malwareContent = json.load(args.malware)
    behaviorContent = json.load(args.behavior)


    ## Process the config file
    process_config(configContent)

    ## Process the CVEs
    process_vulns(reportContent, vulnsContent)
    
    ## Process Malware
    process_malware(reportContent, malwareContent)

    # Process Behaviors
    process_behaviors(reportContent, behaviorContent)

    # Get All Files
    get_all_file()


    args.report.close()
    args.config.close()
    args.vulns.close()
    args.malware.close()
    args.behavior.close()

    outfile = open("findings.json", "w")
    outfile.write(json.dumps(findings))
    outfile.close()

if __name__ == "__main__":
    main()
