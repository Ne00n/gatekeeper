#!/usr/bin/python3
import requests, ipaddress, json, os

network,config,ports = [],[],{}

class gatekeeper:
    def __init__(self):
        dirname, filename = os.path.split(os.path.abspath(__file__))
        global network,config,ports
        print("Loading pmacct")
        with open('/tmp/pmacct.json', 'r') as f:
            network = f.read()
        print("Loading config")
        with open(dirname+'/configs/config.json') as handle:
            config = json.loads(handle.read())
        print("Loading settings")
        with open(dirname+'/configs/settings.json') as handle:
            ports = json.loads(handle.read())

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

    def getLimits(self,src):
        if src in ports:
            return ports[src]
        else:
            return ports['any']

    def getPortCount(self,port,data):
        count = 0
        for entry in data:
            if entry['port_dst'] == int(port): count = count +1
        return count

    def getLocalCount(self,port,data):
        count = 0
        for entry in data:
            if ipaddress.ip_address(entry['ip_src']).is_private and ipaddress.ip_address(entry['ip_dst']).is_private: count = count +1
        return count

    def triggers(self,source):
        for src,data in source.items():
            limits =  self.getLimits(src)
            for port in limits:
                if port == "any":
                    if len(data) >= limits['any'] and limits['any'] != 0:
                        message = self.prepareMessage(data,True)
                        header = f"{src} {port} exceeded {len(data)}/{limits[port]}"
                        print(header)
                        self.notify(header,message)
                elif port == "local":
                    count = self.getLocalCount(port,data)
                    if count >= limits[port] and limits[port] != 0:
                        message = self.prepareMessage(data,True)
                        header = f"{src} {port} exceeded {len(data)}/{limits[port]}"
                        print(header)
                        self.notify(header,message)
                else:
                    count = self.getPortCount(port,data)
                    if count >= limits[port] and limits[port] != 0:
                        message = self.prepareMessage(data,True)
                        header = f"{src} {port} exceeded {len(data)}/{limits[port]}"
                        print(header)
                        self.notify(header,message)

    def prepareMessage(self,data,short=False):
        rows,count = "",0
        for entry in data:
            rows += entry['ip_src']+":"+str(entry['port_src'])+" --> "+entry['ip_dst']+":"+str(entry['port_dst'])+", "+entry['ip_proto'].upper()+", "+str(entry['packets'])+" Packet(s), "+str(entry['bytes'])+" Bytes\n"
            count = count +1
            if short == True and count == 150:
                return rows
        return rows

    def notify(self,title,message,priority='5'):
        for id,row in config.items():
            if row['type'] == "gotify":
                params = (('token', row['token']),)
                payload = {
                            'title': (None, title),
                            'message': (None, message),
                            'priority': (None, priority),
                          }
                response = requests.post(row['server'], params=params, files=payload)

    def run(self):
        print("Parsing pmacct")
        rows = []
        for row in network.split('\n'):
            #Drop empty lines
            if row.strip() == "": continue
            line = json.loads(row)
            #Drop Multicast traffic
            if ipaddress.ip_address(line['ip_dst']).is_multicast: continue
            rows.append(line)
        source = self.sortBySource(rows)
        self.triggers(source)

Gate = gatekeeper()
Gate.run()
