# gatekeeper

Watch the bloody gates

**Dependencies**<br />
```
apt-get install -y pmacct python3
```

**Prepare**<br />
```
cp config.example.json config.json
cp pmacctd.conf /etc/pmacct/pmacctd.conf
python3 interfacer.py
systemctl restart pmacct
```
