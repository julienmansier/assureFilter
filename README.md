# assure2ANALYZE
Python script used to pull out specific details from rl-secure cli to send to Analyze 


## Genereate Require Reports
```
rl-secure report rl-json pkg:rl/test/example_binary@1.0.0 --output-path .
rl-secure find malware pkg:rl/test/example_binary@1.0.0 --no-color >> malware.txt
rl-secure find CVE* pkg:rl/test/example_binary@1.0.0 --no-color >> cve.txt
rl-secure find BH* pkg:rl/test/example_binary@1.0.0 --no-color >> behaviors.txt
```
## Convert the command line output text to JSON
```
python3 vuln2JSON.py cve.txt
python3 mal3JSON.py malware.txt
python3 bh2JSON.py behaviors.txt
```
## Update the Config.json file
- Set malware = true to check for malware
- set suspected = true if you want to included suspected malware (malware-like behaviors)
- set vulnThreshold to a CVSS score to which only vulnerabilities above that score will be checked
- add any desired behaviors to check. A full list of behaviors can be found here: https://docs.secure.software/concepts/behavior-reference

## Run the filtering script
```
python3 assure2ANALYZE.py -c config.json -r report.rl.json -m malware.json -b behaviors.json
```

