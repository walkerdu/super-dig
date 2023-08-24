# super-dig
加强版dig，可以扫描Domain Name对应的所有A记录

## To start using
```
$ git clone https://github.com/walkerdu/super-dig.git
$ cd super-dig
$ make
$ bin/super-dig --ns_file=configs/ns.json -f configs/ip_region.json walkerdu.com
```
将`walkerdu.com`替换成你要扫描的域名

- --ns_file=configs/ns.json：是支持edns client subnet的DNS列表，里面目前只有Google DNS；
- -f configs/ip_region.json：client subnet的ip地址列表，可以根据选择自动删减，目前国内：每个省份三大运营商都有一个，国外每个国家只有一个；

## Output Examples
![image](https://github.com/walkerdu/super-dig/assets/5126855/cbd4777e-4b8a-49b7-9784-4547902812e1)
