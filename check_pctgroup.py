import requests, sys, argparse, os, json, yaml,decimal
#NAGIOSXI PLUGIN TO ALERT WHEN X PERCENT OF A HOSTGROUP ARE IN A DOWN STATE
#SNAPIER

#DEAL WITH THE SELF SIGNED NAGIOS SSL
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#SCRIPT DEFINITION
cname = "check_pctgroup"
cversion = "0.0.4"
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
        hostlistcnt = 0
        members = hd["hostgroup"][0]["members"]['host']
        for i in members:
            memlst.append(i["host_name"])
            hostlistcnt += 1
            
        #TRYING TO MAKE IT MORE EFFICIENT USING ONE SINGLE HOSTSTATUS GRAB
        dwncnt = 0
        hoststats = nagiosxiGenericAPI("objects","hoststatus","","get",auth["url"],auth["apikey"])
        stats = hoststats.json()
        totalhost = stats["recordcount"]
        for h in stats["hoststatus"]:
            if h["host_name"] in memlst and h["current_state"] == 1 and h["current_check_attempt"] >= h["max_check_attempts"]:
                dwncnt += 1    
        
        ##GET THE PERCENTAGE OF DOWN HOSTS
        dwn = (dwncnt / hostlistcnt * 100)
        
        #ROUND PERCENTAGE TO ACCOUNT FOR LARGE HOST COUNT
        dwnpct = round(dwn,4)

        ##EVALUATE THE RETURNED DATA AND EXIT
        ##I CREATE THE EXIT MESSAGE FOR EACH STATE IN THE CASE THE DATA PROVIDED FOR EACH STATE
        ##NEEDS TO HAVE A DIFFERENT SERVICE OUTPUT

        ###FIRST IS WORSE
        if(int(dwnpct) >= int(meta.critical)):
            stateid = 2
            state = checkStateFromCode(stateid)
            msg = ('{} - Hostgroup {} has {}% of {} members down.'.format(state,meta.hostgroup.upper(),dwnpct,hostlistcnt))
            
        ###WARNINING SHOULD BE OPTIONAL SO HERE WE ONLY PROCESS FOR WARNING IF PRESENT
        elif meta.warning and ((int(dwn) < int(meta.critical)) and (int(dwn) >= int(meta.warning))):
            stateid = 1
            state = checkStateFromCode(stateid)
            msg = ('{} - Hostgroup {} has {}% for {} members down.'.format(state,meta.hostgroup.upper(),dwnpct,hostlistcnt))

        ###NOT WARNING NOT CRITICAL IT"S OK
        else:
            #EXIT MESSAGE ENHANCEMENT
            stateid = 0
            state = checkStateFromCode(stateid)
            msg = ('{} - Hostgroup {} has {}% of {} members down.'.format(state,meta.hostgroup.upper(),dwnpct,hostlistcnt))
        
        ###NOT EVERYONE WANTS PERFDATA (WHY?)
        if meta.perfdata:
            if meta.warning and meta.warning != None:
                wrn = meta.warning
            else:
                wrn = ""
            perfdata = (' | group-down-percent={}%;{};{}; group-total-count={}; group-down-count={};'.format(dwnpct,wrn,meta.critical,hostlistcnt,dwncnt))
            msg = msg + perfdata
    
    #UNKNOWNS SERVE A PURPOSE (USE THEM WISELY)
    ##EXIT WITH ERROR MESSAGE 
    except Exception as e:
        stateid = 3
        state = checkStateFromCode(stateid)
        msg = e
    
    #IT'S ALL ABOUT THE EXIT
    finally:            
        nagExit(stateid,msg)
        