# gatekeeper

Watch the bloody gates

**Dependencies**<br />
```
apt-get install -y pmacct python3
```

**Prepare**<br />
```
cp configs/config.example.json configs/config.json
cp configs/settings.example.json configs/settings.json
cp pmacctd.conf /etc/pmacct/pmacctd.conf
python3 interfacer.py
systemctl restart pmacct
```

**Workflow**
Source Filter => Any Filter => Port Filter => Any Filter
