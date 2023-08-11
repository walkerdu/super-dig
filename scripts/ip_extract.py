#/usr/bin/python3

import json

ip_dict = {}
illegal_lines = 0
with open("../data/ip.txt") as ip_obj:
    for line in ip_obj:
        line_list = line.strip().split('|')
        if len(line_list) != 7:
            illegal_lines += 1
            continue
        ip_start = line_list[0]
        country = line_list[2]
        province = line_list[4]
        isp = line_list[6]

        if not country in ip_dict:
            ip_dict[country] = {}
            ip_dict[country][province] = {}
            ip_dict[country][province][isp] = [ip_start] 
        elif not province in ip_dict[country]:
            ip_dict[country][province] = {}
            ip_dict[country][province][isp] = [ip_start] 
        elif not isp in ip_dict[country][province]:
            ip_dict[country][province][isp] = [ip_start] 
        elif len(ip_dict[country][province][isp]) < 2:
            ip_dict[country][province][isp].append(ip_start)


with open("../data/ip_country_1.txt", 'w') as file_obj:
    for country, val1 in ip_dict.items():
        for province, val2 in val1.items():
            for isp, val3 in val2.items():
                file_obj.write(' '.join([country, province, isp]) + ' ' + ' '.join(val3) + '\n')

new_dict = {}
for country, val1 in ip_dict.items():
    china = False 
    if '中国' in country:
        china = True

    if not country in new_dict:
        new_dict[country] = {}

    for province, val2 in val1.items():
        # 国外每个国家只保留两个ip，不看ISP
        if not china:
            province = '0'

        if not province in new_dict[country]:
            new_dict[country][province] = {}

        for isp, val3 in val2.items():
            if not china:
                isp = '0'

            isp_china_big3 = False
            # 剔除非三大运营商
            if china :
                if not ('电信' == isp or '移动' == isp or '联通' == isp):
                    continue

            if not isp in new_dict[country][province]:
                new_dict[country][province][isp] = val3
            elif len(new_dict[country][province][isp]) < 2:
                new_dict[country][province][isp] += val3

json_data = []

with open("../data/ip_country_2.txt", 'w') as file_obj:
    for country, val1 in new_dict.items():
        for province, val2 in val1.items():
            for isp, val3 in val2.items():
                file_obj.write(' '.join([country, province, isp]) + ' ' + ' '.join(val3) + '\n')
                json_data.append({
                    "country": country,
                    "province": province,
                    "isp": isp,
                    "ips": val3 
                    })
with open("../data/ip_country_3.json", 'w') as json_file:
    json.dump(json_data, json_file, ensure_ascii=False, indent=4)


