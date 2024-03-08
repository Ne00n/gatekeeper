# gatekeeper

Watch the bloody gates

**Dependencies**<br />
```
apt-get install -y pmacct python3
```

**Prepare**<br />
```
cd /opt/
git clone https://github.com/Ne00n/gatekeeper.git
cd gatekeeper
cp configs/config.example.json configs/config.json
cp configs/settings.example.json configs/settings.json
cp pmacctd.conf /etc/pmacct/pmacctd.conf
python3 interfacer.py
systemctl enable pmacctd
systemctl restart pmacctd
```

**Workflow**<br />
Source Filter => Any Filter => Port Filter => Any Filter<br />

**Config**<br />
0 = no Alert
