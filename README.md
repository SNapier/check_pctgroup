# check_pctgroup
A monitoring plugin to check status of hostgroup members that are in a down state and alert if a threshold is crossed.

## Basic Usage Information
1. Download both the plaugin and yaml file
2. Edit the yaml file to include either the fqdn or IP address of the nagios instace where the script will execute.
3. Edit the yaml file to include the apikey of a nagiosxi user with API permissions.
4. Upload both the script and yaml file to the NagiosXI Instance ```/usr/local/nagios/libexec/``` directory.
5. Create the NagiosXI command for check_pctgroup
```bash
pyhon3 $USER1$/check_pctgroup.py -e $ARG1$ --hostgroup "$ARG2$" -c $ARG3$ $ARG4$ 
```
6. Create a Service Check to utilize the check_pctgroup command.
  * $ARG1$ contains the nagiosxi environment (dev/prd)
  * $ARG2$ contains the nagiosxi hostgroup name you want to evaluate.
  * $ARG3$ contains the critical threshold
  * $ARG4$ used for passing the optional vairables -w/--warning and -p used to enable nagios perfdata output.  

## Command Line Execution Example
```bash
python3 check_pctgroup.py -e dev --hostgroup "dev-linux-web" -c 10  -w 5 -p
```
