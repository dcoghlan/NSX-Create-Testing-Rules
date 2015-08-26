# NSX-Create-Testing-Rules
A script to create NSX DFW Rules for performance testing. The script will allow you to create up to 997 DFW rules in a single section.

Why only 997 rules? Because there are already 3 rules configured by default in a fresh install, so 997+ 3 = 1000!

##Prerequisites
Requires the Requests libraby to be installed. Requests can be downloaded a from the following URL
http://docs.python-requests.org/en/latest/

##Usage
###Help
```
python nsx-create-testing-rules.py -h
```
Output:
```
usage: nsx-create-testing-rules.py [-h] [--nsxmgr [IP/FQDN]]
                                   [--user [username]]
                                   {add,del} ...

Create a firewall section with test rules.

positional arguments:
  {add,del}
    add               Create new section containing test rules
    del               Delete section containing test rules

optional arguments:
  -h, --help          show this help message and exit
  --nsxmgr [IP/FQDN]  OPTIONAL - NSX Manager hostname, FQDN or IP address
  --user [username]   OPTIONAL - NSX Manager username (default: admin)
```
###add
```
python nsx-create-testing-rules.py add -h
```
Output:
```
usage: nsx-create-testing-rules.py add [-h] --section-name name --rule-count
                                       number

optional arguments:
  -h, --help           show this help message and exit
  --section-name name  Section Name to create
  --rule-count number  Number of rules to create
```
###del
```
python nsx-create-testing-rules.py del -h
```
Output:
```
usage: nsx-create-testing-rules.py del [-h] --section-name name

optional arguments:
  -h, --help           show this help message and exit
  --section-name name  Section Name to delete
```

##Examples
###add
When adding the testing rules, you are required to enter the name of the new section the rules will be created under, and also how many rules you want to create.
```
python nsx-create-testing-rules.py --nsxmgr 10.29.5.211 add --section-name test999 --rule-count 1

NSX Manager details provided by command line                         [   OK   ]
NSX Manager password:
Retrieving ETag                                                      [   OK   ]
Creating section and 1 rule[s] via API                               [   OK   ]
```

###add
If you prefer to hardcode the NSX Manager IP/FQDN and password in the script so you don't always get prompted for them, you can modify and uncomment the following variable towards the top of the script:
```
# nsxMgrPass = 'default'
# nsxMgrHost = '10.29.5.211'
```
Then you should be able to run the script without providing the NSX Manager IP/FQDN or password when invoking the script.
```
python nsx-create-testing-rules.py  add --section-name test999 --rule-count 100

NSX Manager details hard coded                                       [   OK   ]
Retrieving ETag                                                      [   OK   ]
Creating section and 100 rule[s] via API                             [   OK   ]
```

###del
Although I have put the del keyword, it doesn't actually do anything yet. This is one to work on in my spare time.
```
python nsx-create-testing-rules.py del --section-name test999 

NSX Manager details hard coded                                       [   OK   ]
Deleting sections on the to do list!

```
