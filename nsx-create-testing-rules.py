# Author:   Dale Coghlan (www.sneaku.com)
# Date:     26th Aug 2015
# Version:  1.0.1

# ----------------------------------------------------------------------------
# Set some variables. No need to change anything else after this section
#
# nsxMgrPass = 'default'
# nsxMgrHost = '10.29.5.211'
# ----------------------------------------------------------------------------

import argparse
import requests
import getpass

def f_hide_cert_warnings():
    ''' if urllib3 is available, then disable self signed certificate warnings
    otherwise just hide the warnings'''
    try:
        import urllib3
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        import logging
        logging.captureWarnings(True)

def f_load_arguments():
    ''' Configures the command line arguments to be used for this script'''
    # Set the following global variables to be used by other functions
    global username
    global nsxmgr
    global args
    global modeDelete
    global modeAdd
    global sectionName
    global ruleCount
    global appliedTo

    parser = argparse.ArgumentParser(
        description='Create a firewall section with test rules.')
    parser.add_argument(
        '--nsxmgr',\
        help = 'OPTIONAL - NSX Manager hostname, FQDN or IP address',\
        metavar = 'IP/FQDN',\
        dest = 'nsxmgr',\
        nargs = '?',\
        const = 'nsxmgr')
    parser.add_argument(
        '--user',\
        help = 'OPTIONAL - NSX Manager username (default: %(default)s)',\
        metavar = 'username',\
        dest = 'username',\
        nargs = '?',\
        const = 'admin')
    parser.set_defaults(username='admin')

    # Parser arguments for 'del' sub-parser defined below
    delParser = argparse.ArgumentParser(add_help=False)
    delParser.add_argument(
        '--del',\
        help=argparse.SUPPRESS,\
        dest='modeDelete',\
        action='store_true')
    delParser.add_argument(
        '--section-name',\
        help = 'Section Name to delete',\
        metavar = 'name',\
        dest = 'sectionName',\
        required = True)

    # Parser arguments for 'add' sub-parser defined below
    addParser = argparse.ArgumentParser(add_help=False)
    addParser.add_argument('--add',\
        help=argparse.SUPPRESS,\
        dest='modeAdd',\
        action='store_true')
    addParser.add_argument(
        '--section-name',\
        help = 'Section Name to create',\
        metavar = 'name',\
        dest = 'sectionName',\
        required = True)
    addParser.add_argument(
        '--rule-count',\
        help = 'Number of rules to create',\
        metavar = 'number',\
        dest = 'ruleCount',\
        required = True)
    addParser.add_argument(
        '--applied-to',\
        help = 'Where the rules are to be Applied To',\
        metavar = 'edge-id|edge-all|dfw',\
        dest = 'appliedTo',\
        required = True)

    # Sub-Parsers defined
    sp = parser.add_subparsers()
    sp_add = sp.add_parser(
        'add',\
        help='Create new section containing test rules',\
        parents=[addParser])
    sp_del = sp.add_parser('del',\
        help='Delete section containing test rules',\
        parents=[delParser])

    # Load the parser into a variable
    args = parser.parse_args()

    # Reads command line flags and saves them to variables
    username = args.username
    sectionName = args.sectionName

    # If the nsxmgr details are provided on the command line, set the nsxmgr
    # variable to the details entered on the command line
    if args.nsxmgr != None:
        nsxmgr = args.nsxmgr
        print(outputSectionTask.format(
            'NSX Manager details provided by command line','OK'))
    else:
        try:
            # Tries to set the nsxmgr variable to the hardcoded variable at
            # the top of the script
            nsxmgr = nsxMgrHost
            print(outputSectionTask.format(
                'NSX Manager details hard coded','OK'))
        except NameError:
            # If the nsxmgr details are not provided on the command line or
            # hardcoded at the top of the script, alert the user and exit the#
            # script as there is no point in continuing.
            print(outputSectionTask.format(
                'NSX Manager details provided','FAILED'))
            exit(1)

    try:
        modeDelete = args.modeDelete
    except AttributeError:
        modeDelete = None

    try:
        modeAdd = args.modeAdd
    except AttributeError:
        modeAdd = None

    try:
        ruleCount = int(args.ruleCount)
        if (ruleCount < 1) or (ruleCount > 997):
            print(outputSectionTask.format(
                'Number of rules to create is between 1 and 997','FAILED'))
            exit(1)
    except AttributeError:
        ruleCount = None

    try:
        if args.appliedTo.lower() == 'dfw':
            appliedTo = 'DISTRIBUTED_FIREWALL'
        elif args.appliedTo.lower() == 'edge-all':
            appliedTo = 'ALL_EDGES'
        else:
            appliedTo = args.appliedTo
    except:
        appliedTo = None

def f_default_headers():
    global nsx_api_headers

    nsx_api_headers = {'Content-Type': 'application/xml'}

def f_pw_check():
    global password

    # Check to see if the password is hard coded
    try:
        nsxMgrPass
        password = nsxMgrPass
    except NameError:
        password = getpass.getpass(prompt='Enter NSX Manager password:')

def f_set_output_formats():
    ''' Sets basic output formatting '''
    global outputSectionTitle
    global outputSectionTask
    outputSectionTitle = '{0:^79}'
    outputSectionTask = '{0:68} [{1:^8}]'

def f_get_etag():
    url = 'https://%s/api/4.0/firewall/globalroot-0/config' % (nsxmgr)
    response = requests.get((url), headers=nsx_api_headers, 
        auth=(username, password), verify=False)

    if int(response.status_code) != 200:
        print(outputSectionTask.format(
            'Retrieving ETag','FAILED'))
        print(response.status_code)
        print(response.content)
        exit(1)
    else:
        print(outputSectionTask.format(
            'Retrieving ETag','OK'))

    return response.headers['ETag']


def f_generate_fw_rules(count,sectionName):
    xml = ''
    xml += '<section name="%s: %s rules">' % (sectionName,count)
    ipCount = 1
    octet3 = 0
    octet4 = 1
    while ipCount <= count:

        if octet4 > 100:
            octet4 = 1
            octet3 += 1 
        srcIp = '1.1.%s.%s' % (octet3,octet4)
        dstIP = '2.2.%s.%s' % (octet3,octet4)

        xml += '\n<rule disabled="false" logged="false">'\
        '<name>Test_Rule_%s</name>'\
        '<action>%s</action>'\
        '<appliedToList>'\
            '<appliedTo>'\
                '<value>%s</value>'\
                '<isValid>true</isValid>'\
            '</appliedTo>'\
        '</appliedToList>'\
        '<sources excluded="false">'\
            '<source>'\
                '<value>%s</value>'\
                '<type>Ipv4Address</type>'\
                '<isValid>true</isValid>'\
            '</source>'\
        '</sources>'\
        '<destinations excluded="false">'\
            '<destination>'\
                '<value>%s</value>'\
                '<type>Ipv4Address</type>'\
                '<isValid>true</isValid>'\
            '</destination>'\
        '</destinations>'\
        '<services>'\
            '<service>'\
                '<isValid>true</isValid>'\
                '<destinationPort>%s</destinationPort>'\
                '<protocol>6</protocol>'\
                '<protocolName>TCP</protocolName>'\
            '</service>'\
        '</services>'\
        '<direction>inout</direction>'\
        '<packetType>any</packetType>'\
    '</rule>'\
    % (ipCount, 'deny', appliedTo, srcIp, dstIP, ipCount)

        ipCount += 1
        octet4 += 1
    xml += '\n</section>'
    return xml

def f_add_layer3_section(xml,etag):
    url = 'https://%s/api/4.0/firewall/globalroot-0/config/layer3sections'\
    % (nsxmgr)
    nsx_api_headers.update({'if-Match':etag})
    response = requests.post(
        (url), data=xml, headers=nsx_api_headers, auth=(username, password),
        verify=False)

    if int(response.status_code) != 201:
        print(outputSectionTask.format(
            'Creating section and %s rule[s] via API' % (ruleCount),'FAILED'))
        print(response.status_code)
        print(response.content)
        exit(1)
    else:
        print(outputSectionTask.format(
            'Creating section and %s rule[s] via API' % (ruleCount),'OK'))

def f_main_add():
    f_add_layer3_section(
        f_generate_fw_rules(ruleCount,sectionName),f_get_etag())
    exit()

def main():
    f_set_output_formats()
    f_hide_cert_warnings()
    f_default_headers()
    print
    f_load_arguments()
    f_pw_check()

    if modeAdd != None:
        f_main_add()
    elif modeDelete != None:
        print('Deleting sections on the to do list!')
        exit()

    print
if __name__ == '__main__':
    main()

exit()
