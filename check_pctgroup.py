import requests, sys, argparse, os, json, yaml
#NAGIOSXI PLUGIN TO ALERT WHEN X PERCENT OF A HOSTGROUP ARE IN A DOWN STATE
#SNAPIER

#DEAL WITH THE SELF SIGNED NAGIOS SSL
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#SCRIPT DEFINITION
cname = "check_pctgroup"
cversion = "0.0.1"
cpath = os.path.dirname(os.path.realpath(__file__))

##NAGIOSXI DIRECT API CALL
def nagiosxiGenericAPI(resource,endpoint,modifier,method,myurl,mykey):
    
    #URL FOR APICALL TO NAGIOSXI
    url = ("https://{turl}/nagiosxi/api/v1/{resource}/{endpoint}?{modifier}&apikey={akey}".format(turl=myurl,akey=mykey,resource=resource,endpoint=endpoint,modifier=modifier)) 

    #ONLY ALLOW FOR USE OF GET IN THIS INSTANCE
    if method == "get":
        try:
            r = requests.get(url=url,verify=False)
        except Exception as e:
            print("ERROR: %s",e)
            r = False
    else:
        r = False
    return r


##CREDENTAILS USED TO GATHER DATA VIA THE NAGIOSXI API
#PRO TIP: A UNIFIED YML CAN BE USED MULTIPLE PLUGINS  
def nagiosxiAPICreds(meta):
    env = meta.nenv
    with open(cpath+"/check_pctgroup.yaml", "r") as yamlfile:
        try:
            data = yaml.safe_load(yamlfile)
            r = {"url":data[0]["nagios"][env]["url"],"apikey":data[0]["nagios"][env]["apikey"]}
        except Exception as e:
            print("ERROR: %s",e)
            r = False
        finally:
            return r

#STATE FROM STATEID
def checkStateFromCode(i):
    switcher = {
        0: "OK",
        1: "WARNING",
        2: "CRITICAL",
        3: "UNKNOWN"
    }

    #GIVE THE STATE BACK
    return switcher.get(i)

#NAGIOS EXIT
def nagExit(stateid,msg):
    #ENRICH IF NEEDED
    print(msg)
    #EXIT WITH THE STATEID
    sys.exit(stateid)


if __name__ == "__main__" :
    
    #INPUT FROM NAGIOS
    args = argparse.ArgumentParser(prog=cname+"v:"+cversion, formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    #NAGIOSXI TARGET
    args.add_argument(
        "-e","--nenv",
        required=True,
        default=None,
        help="String(nagiosenvironment): NagiosXI Instance definition stored in the yml.(dev,prd)"
    ),
    #HOSTGROUP
    #SINGLE GROUP
    args.add_argument(
        "--hostgroup",
        required=True,
        default=None,
        help="String(hostgroup): NagiosXI hostgroup to evaluate."
    ),
    args.add_argument(
        "-w", "--warning",
        required=False,
        default=None,
        help="String(warning): NagiosXI Warning Value"
    )
    args.add_argument(
        "-c","--critical",
        required=True,
        default=None,
        help="String(critical): NagiosXI Critical Value"
    )
    args.add_argument(
        "-t","--timeout",
        required=False,
        default='30',
        help="int(timeout): NagiosXI check timeout value."
    )
    args.add_argument(
        "-p", "--perfdata",
        required = False,
        action = "store_true",
        help="boolean(perfdata): Include NagiosXI perfdata in check output msg if enabled."
    )

    #PARSE ARGS
    meta = args.parse_args()

    #THE CHECK BODY
    try:
        #COLLECT THE DATA
        ##NAGIOS API CREDS
        auth = nagiosxiAPICreds(meta)

        ##GET THE HOSTGROUPMEMBERS FOR THE TARGET GROUP
        modhg = "&hostgroup_name={}".format(meta.hostgroup)
        hostgm = nagiosxiGenericAPI("objects","hostgroupmembers",modhg,"get",auth["url"],auth["apikey"])
        hd = hostgm.json()

        ##BUILD THE LIST 
        memlst = list()
        totalhost = 0
        members = hd["hostgroup"][0]["members"]['host']
        for i in members:
            memlst.append(i["host_name"])
            totalhost += 1
        
        ##GET STATUS OF the LIST OF HOSTGROUP MEMBERS
        nhl = ','.join(memlst)
        modhgm = "&host_name=in:{}&current_state=1".format(nhl)
        hoststats = nagiosxiGenericAPI("objects","hoststatus",modhgm,"get",auth["url"],auth["apikey"])
        stats = hoststats.json()

        ##GET THE PERCENTAGE OF DOWN HOSTS
        dwn = (float(stats["recordcount"]) / totalhost * 100)
        
        ##EVALUATE THE RETURNED DATA
        ###FIRST IS WORSE
        if(int(dwn) >= int(meta.critical)):
            stateid = 2
            state = checkStateFromCode(stateid)
            msg = ('{} - Hostgroup {} has {}% members down.'.format(state,meta.hostgroup,dwn))
            
        ###WARNINING SHOULD BE OPTIONAL SO HERE WE ONLY PROCESS FOR WARNING IF PRESENT
        elif meta.warning and ((int(dwn) < int(meta.critical)) and (int(dwn) >= int(meta.warning))):
            stateid = 1
            state = checkStateFromCode(stateid)
            msg = ('{} - Hostgroup {} has {}% members down.'.format(state,meta.hostgroup,dwn))

        ###NOT WARNING NOT CRITICAL IT"S OK
        else:
            stateid = 0
            state = checkStateFromCode(stateid)
            msg = ('{} - All {} members of {} are UP.'.format(state,totalhost,meta.hostgroup))
        
        ###NOT EVERYONE WANTS PERFDATA (WHY?)
        if meta.perfdata:
            if meta.warning and meta.warning != None:
                wrn = meta.warning
            else:
                wrn = ""
            perfdata = (' | group-down-percent={}%;{};{}; group-total-count={}; group-down-count={};'.format(dwn,wrn,meta.critical,totalhost,stats["recordcount"]))
            msg = msg + perfdata
    
    #UNKNOWNS SERVE A PURPOSE (USE THEM WISELY)
    except Exception as e:
        stateid = 3
        state = checkStateFromCode(stateid)
        msg = e
    
    #IT'S ALL ABOUT THE EXIT
    finally:            
        nagExit(stateid,msg)
        