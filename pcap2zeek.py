#! /bin/python

import argparse
import re
import os
import sys
import shutil
from subprocess import call,check_output
import json

# yeah, lots of globals, I do not forsee this code getting 
# larger, but if so, this should be handled in a more scalable
# fashion
global zeekExec
global zeekLogDir
global createDir
global config_d
global carg
zeekExec = "/opt/zeek/bin/zeek"
zeekLogDir = "/home/zeek/logs/current"
createDir = "/home/zeek/convert/newBro"

datetime_re = re.compile(
    r'(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})'
    r'[T ](?P<hour>\d{1,2}):(?P<minute>\d{1,2})'
    r'(?::(?P<second>\d{1,2})(?:\.(?P<microsecond>\d{1,6})\d{0,6})?)?'
    r'(?P<tzinfo>Z|[+-]\d{2}(?::?\d{2})?)?$'
)

# config file example:
#    # configuration file for pcap2bro.py
#    # JSON format, with some xtras:
#    # - Allows for 'pretty' print whitespace style in order for
#    #   us humans to read it.
#    # - Allows for coments = '#' as first character on a line
#    # 
#    {
#    # general configuration
#    # "gen" section, this section and its individual values
#    #       are not required
#     "gen": {
#      "zeekExec": "/opt/zeek/bin/zeek",
#      "zeekLogDir": "/home/zeek/logs/current",
#      "createDir": "/home/zeek/convert/newBro"
#     },
#    # REQUIRED section, must have 1+ hash entry with all three values
#    # "pcap_conf", configuration for pcap file-set processing
#    # "hash-name" : name indicative of pcap file-set derivation
#    # "from"  : pcap file-set location
#    # "touch" : touch files location, used to indicate proccessed pcaps
#    # "add"   : unique tag to add to zeek log names, to keep different
#    #           zeek file names unique between pcap file-sets
#    #           
#     "pcap_conf": {
#      "tisdns": {
#       "from": "/home/capture/tisdns",
#       "touch": "/home/zeek/convert/touched/tisdns",
#       "add": "tisdns"
#      },
#      "johndns": {
#       "from": "/home/capture/johndns",
#       "touch": "/home/zeek/convert/touched/johndns",
#       "add": "johndns"
#      },
#      "peanutsmtp": {
#       "from": "/home/capture/peanutcap",
#       "touch": "/home/zeek/convert/touched/peanutcap",
#       "add": "peanutsmtp"
#      }
#     }
#    }


def copy_bro_logs( name, config, filename):
    global zeekLogDir
    global createDir
    
    for fl in  os.listdir(createDir) :
        (front, ext) = os.path.splitext(fl)
        if ( ext == ".log" ):
            toName = zeekLogDir + "/" + front + "-" + config["add"] + "-" + os.path.basename(filename) + ext
            shutil.move(fl, toName)
            print( "Moved %s to %s " % (fl, toName) )
# end copy_bro_logs


def create_bro_logs( name, config, filename):
    global carg
    global zeekExec

    if carg.debug :
        print("create_bro_logs : debug : no action taken")
        return 1
    
    if ( shutil.rmtree(createDir) ) :
        print( "FAILED remove %s " % (createDir) )
    elif carg.verbose :
        print( "removed %s " % (createDir) )


    if ( (not  os.mkdir(createDir)) and
         (not  os.chdir(createDir)) and
         ( os.getcwd() == createDir ) ):
        if carg.verbose :
            print( "created and chdir to %s : %s " % (createDir, os.getcwd()) )
        print( "Bro output for '%s' : " % (filename) )
        if ( not call( [zeekExec, "-r", filename] ) ):
            copy_bro_logs( name, config, filename)
        else:
            return 0

    else :
        print( "FAILED created/chdir to %s : %s " % (createDir, os.getcwd()) )
        return 0
    
    return 1
# end create-bro-logs

# loads carg and global config values
def args_and_config(argv) :
    global zeekExec
    global zeekLogDir
    global createDir
    global carg
    global config_d

    p = argparse.ArgumentParser()
    p.add_argument("-z", "--zeekExec",
                   help="Location of zeek exeutable. Default: " + zeekExec)
    p.add_argument("-l", "--zeekLogDir",
                   help="Location to store created zeek files: Default: " + zeekLogDir)
    p.add_argument("-t", "--createDir",
                   help="Directory to use for temp zeek files. Default: " + createDir)
    p.add_argument("-c", "--config",
                   help="Config file to use. Command line opts overides. Default: $HOME/pcap2zeek.conf", 
                   default= os.environ['HOME'] + "/pcap2zeek.conf")
    p.add_argument("-v", "--verbose", help="Verbose output", 
                   action="store_true")
    p.add_argument("-d", "--debug", help="Check config, but do not do any actions", 
                   action="store_true")

    carg = p.parse_args(argv)

    if not os.path.isfile(carg.config) or not os.access(carg.config, os.R_OK) :
        print("\nError : configuration file does not exist or is not readable: \'%s\'\n" % (carg.config))
        p.print_help()
        exit(1)

    # file to list
    conf_fp   = open(carg.config, 'r')
    conf_list = conf_fp.readlines()
    conf_fp.close()

    # get rid of comments
    reg_comment = re.compile("^#.*")
    conf_list = [i for i in conf_list if not reg_comment.search(i)]
    # normalize whitespace,
    conf_str = re.sub("\s+"," ", " ".join(conf_list))
    # get rid of commas before '}', JSON does not allow that, but I do
    conf_str = re.sub("\s*,\s*}","}", conf_str)
    # convert json to dict
    conf = json.loads(conf_str)

    if carg.verbose :
        print("config file: \'%s\'" % (carg.config))
        print(json.dumps(conf, indent=1))
    
    config_d = conf["pcap_conf"]

    if "gen" in conf.keys() :
        if "zeekExec" in conf["gen"].keys() :
            zeekExec = conf["gen"]["zeekExec"]
        if "zeekLogDir" in conf["gen"].keys() :
            zeekLogDir = conf["gen"]["zeekLogDir"]
        if "createDir" in conf["gen"].keys() :
            createDir = conf["gen"]["createDir"]

    # prioritize command line, check it last
    if carg.zeekExec :
        zeekExec = carg.zeekExec
    if carg.zeekLogDir :
        zeekLogDir = carg.zeekLogDir
    if carg.createDir :
        createDir = carg.createDir

# end args_and_config


# 
# MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN MAIN
#

def main(argv) :
    global carg
    global config_d
    
    args_and_config(argv)

    for srcName, srcConf in config_d.items():

        filelist = os.listdir(srcConf["from"])

        for fl in filelist :

            if ( not os.path.exists(srcConf["touch"]) ) :
                os.mkdir(srcConf["touch"])

            fromFl = srcConf["from"]  + "/" + fl
            toFl   = srcConf["touch"] + "/" + fl
            isNew  = False

            if ( not os.path.exists(toFl) ) :
                isNew = True
                print( "\n%s: \'%s\' doesn't exist, creating bro logs" %
                       (srcName, toFl) )

            elif ( os.path.getmtime(fromFl) > os.path.getmtime(toFl) ) :
                isNew = True
                print( "\n%s is %d mins NEWER\nre-creating bro logs" %
                       ( fromFl,
                         ((os.path.getmtime(fromFl) - 
                           os.path.getmtime(toFl))/60) ) )

            if isNew :
                if create_bro_logs(srcName, srcConf, fromFl) :
                    if carg.debug :
                        print("bro logs faux created : debug : no touching")
                        # skip touching
                        continue;
                    if carg.verbose : print( "Created bro logs" )

                    if ( not call(["touch", toFl]) ) :
                        print( "Touched %s" % ( toFl ) )
                    else :
                        print( "FAILED Touching %s"  % ( toFl ) )
                else :
                    print( "FAILED to create bro logs for : %s : %s" %
                           ( srcName, fromFl ) )

    # end for LOOP
# end MAIN
    
if __name__ == "__main__":
    main(sys.argv[1:])

