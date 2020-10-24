#!/usr/bin/python3
import requests, json

ports = {'21':5, '22':5, '25':5, '80':2, '443':2, '6667':2, '6881':500}
network,config = [],[]

class gatekeeper:
    def __init__(self):
        global network,config
        print("Loading pmacct")
        with open('/tmp/pmacct.json', 'r') as f:
            network = f.read()
        print("Loading config")
        with open('/root/gatekeeper/config.json') as handle:
            config = json.loads(handle.read())

    def sortBySource(self,rows):
        source = {}
        for row in rows:
            try:
                tmp = source[row['ip_src']]
                tmp = tmp + (row,)
                source[row['ip_src']] = tmp
            except:
                source[row['ip_src']] = {}
                source[row['ip_src']] = (row,)
        return source

    def triggers(self,source):
        for src,data in source.items():
            #Any source > 350 connections within 5 minutes
            if len(data) / 5 > 350:
                message = self.prepareMessage(data,True)
                self.notify(src+" exceeded 350/"+str(round(len(data) / 5))+" Connections",message)

    def prepareMessage(self,data,short=False):
        rows,count = "",0
        for entry in data:
            rows += entry['ip_src']+":"+str(entry['port_src'])+" --> "+entry['ip_dst']+":"+str(entry['port_dst'])+", "+entry['ip_proto'].upper()+", "+str(entry['packets'])+" Packet(s), "+str(entry['bytes'])+" Bytes\n"
            count = count +1
            if short == True and count == 40:
                return rows
        return rows

    def notify(self,title,message,priority='5'):
        #Gotify
        params = (('token', config['token']),)
        payload = {
                    'title': (None, title),
                    'message': (None, message),
                    'priority': (None, priority),
                  }
        response = requests.post(config['server'], params=params, files=payload)

    def run(self):
        print("Parsing pmacct")
        rows = []
        for row in network.split('\n'):
            #Drop empty lines
            if row.strip() == "": continue
            line = json.loads(row)
            #Drop Multicast traffic
            if '239.255.255.' in line['ip_dst']: continue
            if '224.0.0.' in line['ip_dst']: continue
            if 'ff02::1' in line['ip_dst']: continue
            rows.append(line)
        source = self.sortBySource(rows)
        self.triggers(source)

Gate = gatekeeper()
Gate.run()
