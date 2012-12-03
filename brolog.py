#!/usr/bin/env python
import sys,time,os,threading,Queue,datetime,signal,imp,urlparse,pprint,json,csv

"""
### BEGIN CONFIG
"""
indx = []
stph = []
methods = ['GET','POST','HEAD','OPTIONS']
response_codes = ['200','404','302','301','402','403','500']

"""    
Used the downloader and thread handler 
from: https://github.com/melpomene/I2P-Pastebin-scraper/blob/master/scrape.py
"""

def print_err(*args):
    sys.stderr.write(' '.join(map(str,args)) + '\n')

def print_banner():
    # Header Start    
    color = '\033[91m'
    endcolor = '\033[0m'
    head = ['','brolog.py - poppin collars not boxin',
            'ver: 0.99 [beta]','Written by PLXSERT','','Twitter',
            '@PLXSERT','Email: plxsert@prolexic.com','To Exit Press Control-C','']
    print_err(color)
    print_err('#'*60)
    for lines in head:
        print_err('#'+lines.center(58,' ')+'#')
    print_err('#'*60+endcolor+'\n')
    # Header end

def exit(message):
    sys.exit(message)

def signal_handler(signal, frame):
    print_err("Goooh Bye!")
    exit(0)

"""
#########
#########    Inputer 
#########     
"""

def add(weblog_line,config):
    if config["input"] == 'sys.stdin':
        print "sys"
        for lines in sys.stdin.readlines():
            weblog_line.put(lines)
    else:
        try:
            file = config["input"].strip()
            fhandler = open(file ,'ro')
            for lines in fhandler.readlines():
                weblog_line.put(lines)
            fhandler.close()
        except:
            exit("0 - bad filename, try fullpath")

"""
#########
#########    Parser 
#########     
"""

def parser(weblog_line,output_log,config):
    while True:
        line = weblog_line.get()
        susp_files = ["/indx.php","/define.inc.php",
                      "/LICENSE.php","/INSTALL.php"
                      "/index.inc.php","/settings.class.php"]
        for files in susp_files:
            if line.find(files) != -1:
                response = indx(line)
                #response should be an dictionary
                output_log.put(response)
        if line.find("/stph.php") != -1:
            response = stph(line)
            #response should be an dictionary
            output_log.put(response)
        if line.find("/stcp.php") != -1:
            response = stph(line)
            #response should be an dictionary
            output_log.put(response)
        if line.find("/stcurl.php") != -1:
            response = stph(line)
            #response should be an dictionary
            output_log.put(response)
        weblog_line.task_done()

def decode_base64(data):
    """Decode base64, padding being optional.

    :param data: Base64 data as an ASCII byte string
    :returns: The decoded byte string.
    
    stolen from http://stackoverflow.com/questions/6416131/python-add-new-item-to-dictionary
    """
    import base64
    missing_padding = 4 - len(data) % 4
    if missing_padding:
        data += b'='* missing_padding
    return base64.decodestring(data)

def decode_page(page):
    input = page.encode('rot13')
    s_str = input[2:]
    e_str = input[0:2]
    str(s_str)+str(e_str)
    decoded = decode_base64(str(s_str)+str(e_str))
    return(decoded)

def parse_epoch(timer):
    import datetime
    date = datetime.datetime.utcfromtimestamp(float(timer))
    isodate = date.strftime("%Y%m%dT%H%M%S")
    return(isodate)

def indx(line):
    lines = line
    line = " oops"
    for lookups in methods:
        if lines.find(lookups) != -1:
            try:
                status = lines.strip("""\"""").strip()
                url = status[status.find(lookups+" /"):]
                url = url[:url.find("HTTP")]
                url = url.strip() 
                url = url[len(lookups)+1:]
                bas = urlparse.urlparse(url)
                urlq = urlparse.parse_qs((bas.query))
                path = bas.path
            except:
                print "Error: ",lines
            try:
                ip = lines[0:]
                ip = ip[:ip.find(" -")]
            except:
                ip = None                    
            
            for response in response_codes:
                if lines.find(response) != -1:
                    res = response
                    break
                else:
                    res = "UNKNOWN" 
            method = lookups
            
            try:
                action = urlq["action"][0]
            except:
                action = "None"
            
            try:
                status = lines.strip("""\"""").strip()
                url = status[status.find(method+" /"):]
                url = url[:url.find("HTTP")]
                url = url.strip() 
                url = url[len(method)+1:]    
                if url.find("?") != -1:
                    url = url[:url.find("?")]
                    rev_url = url[::-1]
                    file = rev_url[:rev_url.find("/")][::-1]
                else:
                    rev_url = url[::-1]
                    file = rev_url[:rev_url.find("/")][::-1]
            except:
                file="None"
            
            try:
                atime = lines[lines.find("["):]
                atime = atime[1:atime.find("]")]
            except:
                atime = None
            
            data = {"req":method, "full":lines, "action":action,
                    "srcip":ip,"response":res,"path":path,
                    "file":file,"format":"0","atime":atime,
                    "full":lines}
    return(data)

def stph(lines):
    for lookups in methods:
        if lines.find(lookups) != -1:
            try:
                status = lines.strip("""\"""").strip()
                url = status[status.find(lookups+" /"):]
                url = url[:url.find("HTTP")]
                url = url.strip() 
                url = url[len(lookups)+1:]
                bas = urlparse.urlparse(url)
                urlq = urlparse.parse_qs((bas.query))
                path = bas.path
            except:
                print "Error: ",lines
            try:
                ip = lines[0:]
                ip = ip[:ip.find(" -")]
            except:
                ip = None                    
            try:
                atime = lines[lines.find("["):]
                atime = atime[1:atime.find("]")]
            except:
                atime = None
            
            for response in response_codes:
                if lines.find(response) != -1:
                    res = response
                    break
                else:
                    res = "UNKNOWN" 
            method = lookups    
            try:
                page = urlq["page"][0]
            except:
                page = "None"
            try:
                decoded_page = decode_page(urlq["page"][0])
            except:
                decoded_page = "None"
            try:
                try:
                    stime = parse_epoch(urlq["time_s"][0])
                except: 
                    stime = urlq["time_s"][0]
            except:
                stime = "None"
            try:
                try:
                    etime = parse_epoch(urlq["time_e"][0])
                except: 
                    etime = urlq["time_e"][0]
            except:
                etime = "None"
            try:
                action = urlq["action"][0]
            except:
                action = "None"
            
            try:
                status = lines.strip("""\"""").strip()
                url = status[status.find(method+" /"):]
                url = url[:url.find("HTTP")]
                url = url.strip() 
                url = url[len(method)+1:]    
                if url.find("?") != -1:
                    url = url[:url.find("?")]
                    rev_url = url[::-1]
                    file = rev_url[:rev_url.find("/")][::-1]
                else:
                    rev_url = url[::-1]
                    file = rev_url[:rev_url.find("/")][::-1]
            except:
                file="None"
            
            data = {"page":page,"stime":stime,"etime":etime,
                    "atime":atime,"req":method, "full":lines,
                    "srcip":ip,"response":res,"path":path,
                    "decoded_page":decoded_page,"action":action,
                    "file":file,"format":"1"}
            return(data)

"""
#########
#########    Output Formats
#########     
"""

def output(output_log,config):
    while True:
        #pprint.pprint(output_log.get())
        #print json.dumps(output_log.get())
        output = output_log.get()
        if config["json"] is True:
            output_json(output,config)
        elif config["csv"] is True:
            output_csv(output,config)
        else:
            output_cymru(output,config)
            
        output_log.task_done()
        #print("Queue Size is currently " + str(output_log.qsize()))

def output_csv(output,config):
        if output["format"] == "0":
            #pprint.pprint(output)
            line = [output['atime'], output['response'],output['file'],
                    output['srcip'],output['req'],
                    str("v" + output['format'])]
            print ",".join(line)
                
            if config["write"] is True:
                with open(str(str(config["filename"])+"csv-v0.txt"), 'a') as csvfile:
                    writer = csv.writer(csvfile,delimiter=',',
                                        quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    writer.writerow(line)
            
        if output["format"] == "1":
            line = [output['atime'],output['response'],
                  output['file'],output['srcip'],
                  output['decoded_page'],output['action'],
                  output['stime'],output['etime'],
                  output['req'],str("v" + output['format'])]
            
            print ",".join(line)
            
            if config["write"] is True:
                with open(str(str(config["filename"])+"csv-v1.txt"), 'a') as csvfile:
                    writer = csv.writer(csvfile,delimiter=',',
                                        quotechar='"', quoting=csv.QUOTE_MINIMAL)
                    writer.writerow(line)
            

def output_json(output,config):
    if config["write"] is True:
        handler = open(config["filename"]+"json.txt","a")
        handler.write(json.dumps(output))
        handler.close()
    print json.dumps(output)

def output_cymru(output,config):
        if output["format"] == "0":
            #pprint.pprint(output)
            d = " | " #delieter
            line = (output['atime'] + d + output['response'] + \
                  d + output['file'] + d + output['srcip'] + \
                  d + output['req'] + d + str("v" + output['format']))
            if config["write"] is True:
                handler = open(config["filename"]+"default.txt","a")
                handler.write(line+"\n")
                handler.close()
            print line
        if output["format"] == "1":
            d = " | " #delieter
            line = (output['atime'] + d + output['response'] + \
                  d + output['file'] + d + output['srcip'] + \
                  d + output['decoded_page'] + d + output['action'] + \
                  d + output['stime'] + d + output['etime'] + \
                  d + output['req'] + d + str("v" + output['format']))
            if config["write"] is True:
                handler = open(config["filename"]+"default.txt","a")
                handler.write(line+"\n")
                handler.close()
            print line

def main(config):
    print config
    """spy vs. spy - black spy wins"""
    """print banner"""
    print_banner()
    ssecs = time.time()
    """Config"""
    weblog_line = Queue.Queue()
    output_log = Queue.Queue()             
    signal.signal(signal.SIGINT, signal_handler)
    
    """setup collectors"""
    num_workers = 1
    for i in range(num_workers):
        w = threading.Thread(target=add, args=(weblog_line,config,))
        w.setDaemon(True)
        w.start()
    
    """start the parsers""" 
    num_workers = 3
    for i in range(num_workers):
        p = threading.Thread(target=parser, args=(weblog_line,output_log,config,))
        p.setDaemon(True)
        p.start()
    
    """setup output module"""
    num_workers = 1
    for i in range(num_workers):
        o = threading.Thread(target=output, args=(output_log,config,))
        o.setDaemon(True)
        o.start()
    signal.pause()
    p.join()
    o.join()
    w.join()
    esecs = time.time()
    print str(ssecs - esecs) + str(" seconds to complete")

def config(argys):
    import argparse
    config = {}
    
    if ("-h" or "--help") in argys:
        print_banner()
    parser = argparse.ArgumentParser(description='Parse logs from compromised brobots' + \
                                     "default input is standard in" + \
                                     "  Ex: cat log.txt | python brolog.py -j" + \
                                     "This example would parse log.txt and output json")
    
    parser.add_argument("-j",'--json',help='Output in JSON Format', 
                        required=False,action='store_true')
    
    parser.add_argument("-c",'--csv',help='Output in CSV Format', 
                        required=False, action='store_true')
    
    parser.add_argument("-w",'--write',
                        help='write output to file -f to set filename " + \
                        "(defualt filename base is out.brolog-*.txt', 
                        required=False, action='store_true')

    parser.add_argument('-i','--input', 
                        help='Input filename if stdin default is not to be used',
                        required=False,default="sys.stdin",action="store")
    
    parser.add_argument('-f','--filename', 
                        help='Basefile name for outputting requires -w flag to be set',
                        required=False,default="out.brolog-",action="store")
    
    config = vars(parser.parse_args(argys))
    main(config)

if __name__ == '__main__':
    config(sys.argv[1:])