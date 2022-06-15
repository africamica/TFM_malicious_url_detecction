from  lexical_functions import *
from hostname_functions import *
from aux_functions import *
from ctypes import sizeof
import json, tempfile
import whois
import zipfile
import io
import csv
import sys, argparse, pprint
import iptools
from socket import gethostbyname
from operator import truediv
from pathlib import Path
from statistics import mean
from webbrowser import get
from datetime import datetime
from shodan import Shodan
from socket import gethostbyname
from requests import get
from urllib.parse import urlparse
from re import compile
from json import dump, loads
from time import sleep
from shodan import Shodan
from ipwhois import IPWhois
from waybackpy import cdx_snapshot
from waybackpy import WaybackMachineCDXServerAPI
import ipwhois
import pandas as pd
import os
import time
import re
import warnings

warnings.filterwarnings("ignore")

shodan_key='9ros0wdi6E1beiLW4fehD2PQx84Tm1z3'
ShodanApi= Shodan(shodan_key)


#DATAFRAME ------------------------------------------------------------
#Vamos a crear dos DATAFRAMES: 
# 1. Fila por cada ristra de parámetros calculados de una URL {nombre_parametro, valor_parametro}
# 2. Matriz columna con etiqueta de 'malicious' o 'not_malicious' en otra lista pero 
#    en la misma posición.
df=pd.DataFrame(columns=['len_url','len_hostname','len_path','len_param','long_token_host','long_token_path','long_token_param','Long_token_URL','hostPathRatio','hostParamRatio','hostUrlRatio','pathUrlRatio','paramUrlRatio','count_special_char_url','count_special_char_hostname','count_special_char_path','count_special_char_param', 'count_digits_url','count_digits_hostname','count_digits_path','count_digits_param','count_letter_url','count_letter_hostname','count_letter_path','count_letter_param','count_tokens_hostname','count_tokens_path','count_tokens_param','count_non_alpha_url','count_non_alpha_hostname','count_non_alpha_path','count_non_alpha_param'
,'count_periodt_url','count_periodt_hostname','count_periodt_path','count_periodt_param','case_changes_url','case_changes_hostname','case_changes_path,','case_changes_param','pattern_char_url','pattern_char_hostname','pattern_char_path','pattern_char_param','is_tld','out_ip_host','cisco_in_hostname','cisco_out_url','key_client','key_admin','key_server','key_login','vowel_consonant','digit_letter','avg_tokens','continuity_rate','number_of_subdomains','age_host','intented_life_span','life_remaining','ttl_from_registration','num_open_ports','is_live','connection_speed','days_since_update_date','days_since_first_seen','days_since_last_seen','average_update_frequency','registration_country','hosting_country','isp'])


Y=pd.DataFrame(columns=['label_is_malicious'])


#Crear patron expresión regular ----------------------------------------------------------
pattern=re.compile(r'dstip=(?P<dst_ip>\S+).*?service="(?P<var_service>\S+)".*?hostname="(?P<var_hostname>\S+)".*?action\=\"(?P<var_action>\S+)".*?url\=\"(?P<var_url>\S+)\"')


#CISCO UMBRELLA TOP DOMAINS---------------------------------------
#Creamos lista con TOP 1MILLON de dominios mas populares proporcionados
# por Cisco
with zipfile.ZipFile("top-1m.csv.zip") as zipFile:
    for fname in zipFile.infolist():
        with zipFile.open(fname) as file:
            file= io.TextIOWrapper(file,encoding="utf-8")
            domain_list=[]
            reader=csv.reader(file)
            amr_csv=list(reader)

            for line in amr_csv:
                domain_list.append(line[1])
            

tld_list=[]
list=[]
with open('tld_list.txt') as fname:
    for lineas in fname:
        tld_list.extend(lineas.split(" "))

inFile = open("pass_logs_prueba.txt", 'rb')

for line in inFile: 
        for match in re.finditer(pattern,str(line)):
            print("MATCH")
            dict={"dst_ip":match["dst_ip"],"service":match["var_service"],"hostname":match["var_hostname"],"action":match["var_action"],"url":match["var_url"]}
            list.append(dict)

             #Calcular PARAMS
            hostname_url=dict["hostname"]
            path_param_url=dict["url"]
            [path_url,param_url]=split_path_param(path_param_url)
            service_url=dict["service"]
            ip_url=dict["dst_ip"] 
            url=whole_url(service_url,hostname_url,path_param_url)
            snapshots=get_snapshots(url)
            action=dict["action"]

        
            if  action=='blocked':
                    #La URL SÍ ha sido detectada como maliciosa
                    action=1
            else:
                    #La URL NO ha sido detectado como maliciosa
                    action=0

            Y.append({'label_is_malicious':action},ignore_index=True)

            #CALCULATE FEATURES ----------------------------------------------------------------------------------

            #Lexical features *********
        
            #Length features --------------
            length_url_calc=len_url(whole_url)
            length_hostname_calc=len_hostname(hostname_url)
            length_path_calc=len_path(path_url)
            length_param_calc=len_param(param_url)
            long_token_host_calc=long_token_host(hostname_url)
            long_token_path_calc=long_token_path(path_url)
            long_token_param_calc=long_token_param(param_url)
            long_token_url_calc=Long_token_URL(hostname_url,path_url,param_url)
            hostPathRatio_calc=hostPathRatio(hostname_url,path_url)
            hostParamRatio_calc=hostParamRatio(hostname_url,param_url)
            hostURLRatio_calc=hostUrlRatio(hostname_url,whole_url)
            pathUrlRatio_calc=pathUrlRatio(whole_url,path_url)
            paramUrlRatio_calc=paramUrlRatio(whole_url,param_url)

            #Counting features --------------------
            count_special_char_url_calc=count_special_char(url)
            count_special_char_hostname_calc=count_special_char(hostname_url)
            count_special_char_path_calc=count_special_char(path_url)
            count_special_char_param_calc=count_special_char(param_url)
            count_digits_url_calc=count_digits(url)
            count_digits_hostname_calc=count_digits(hostname_url)
            count_digits_path_calc=count_digits(path_url)
            count_digits_param_calc=count_digits(param_url)
            count_letter_url_calc=count_letter(url)
            count_letter_hostname_calc=count_letter(hostname_url)
            count_letter_path_calc=count_letter(path_url)
            count_letter_param_calc=count_letter(param_url)
            [tokens_hostname,tokens_path,tokens_param]=count_token(hostname_url,path_url,param_url)
            count_non_alpha_url_calc=count_nonalpha(url)
            count_non_alpha_hostname_calc=count_nonalpha(hostname_url)
            count_non_alpha_path_calc=count_nonalpha(path_url)
            count_non_alpha_param_calc=count_nonalpha(param_url)
            count_periodt_url_calc=count_periodt(url)
            count_periodt_hostname_calc=count_nonalpha(hostname_url)
            count_periodt_path_calc=count_nonalpha(path_url)
            count_periodt_param_calc=count_nonalpha(param_url)

            #Pattern Features --------------
            case_changes_url_calc=case_changes(url)
            case_changes_hostname_calc=case_changes(hostname_url)
            case_changes_path_calc=case_changes(path_url)
            case_changes_param_calc=case_changes(param_url)
            pattern_char_url_calc=pattern_char(url)
            pattern_char_hostname_calc=pattern_char(hostname_url)
            pattern_char_path_calc=pattern_char(path_url)
            pattern_char_param_calc=pattern_char(param_url)

            #Binary features----------------------
            is_tld=tld(hostname_url,url)
            out_ip_host_calc=out_ip_host(hostname_url)
            cisco_in_hostname_calc=cisco_in_hostname(hostname_url,domain_list)
            cisco_out_hostname_calc=cisco_out_url(path_param_url,domain_list)
            key_client_clac=key_client(url)
            key_admin_clac=key_admin(url)
            key_server_clac=key_server(url)
            key_login_clac=key_login(url)

            #Ratio features -------------
            vowel_consonant_calc=vowel_consonant(url)
            digit_letter_calc=digit_letter(url)
            avg_tokens_calc=avg_tokens(hostname_url,path_url,param_url)
            continuity_rate_calc=continuity_rate(url)

            #HOSTBASED FEATURES ###################################
            shodan_host=shodan_get_host(ShodanApi,ip_url)
            #Comprobar si el TLD es válido para consultar API WHOIS
            current_tld=obtain_tld(hostname_url)
            current_tld="."+str(current_tld)
            is_valid=valid_tld(current_tld,tld_list)

            #Si el hostname es una IP o el hostname tiene un tld inválido no se pueden realizar querys a whois
            if (out_ip_host(hostname_url)==True) or (is_valid==False):
                number_of_subdomains_calc=1
                age_calc=0
                intented_life_span_calc=0
                life_remaining_calc=0
                ttl_from_registration_calc=0
                days_since_update=0
                registration_country_calc="Unknown"
        
            else: 
                number_of_subdomains_calc=number_of_subdomains(ip_url,shodan_host)
                registration_country_calc=registration_country(hostname_url)
                age_calc=age_host(hostname_url)
                intented_life_span_calc=intented_life_span(hostname_url)
                life_remaining_calc=life_remaining(hostname_url)
                ttl_from_registration_calc=ttl_from_registration(url,hostname_url)
                days_since_update=days_since_update_date(hostname_url)

            #Resto de parámetros hostname-based que se pueden calcular aun con hostname siendo una IP
            num_open_ports_calc=num_open_ports(shodan_host)
            is_live_calc=is_live(url)
            connection_speed_calc=connection_speed(url)
            days_since_first_seen_calc=days_since_first_seen(snapshots)
            days_since_last_seen_calc=days_since_last_seen(snapshots)
            average_update_frequency_calc=average_update_frequency(snapshots)
            hosting_country_calc=hosting_country(shodan_host)
            isp_calc=isp(shodan_host)

            df=df.append({'len_url':length_url_calc,'len_hostname':length_hostname_calc,'len_path':length_path_calc,'len_param':length_param_calc,'long_token_host':long_token_host_calc,'long_token_path':long_token_path_calc,'long_token_param':long_token_param_calc,'Long_token_URL':long_token_url_calc,'hostPathRatio':hostPathRatio_calc,'hostParamRatio':hostParamRatio_calc,'hostUrlRatio':hostURLRatio_calc,'pathUrlRatio':pathUrlRatio_calc,'paramUrlRatio':paramUrlRatio,'count_special_char_url':count_special_char_url_calc,'count_special_char_hostname':count_special_char_hostname_calc,'count_special_char_path':count_special_char_hostname_calc,'count_special_char_param':count_special_char_param_calc, 'count_digits_url':count_digits_url_calc,'count_digits_hostname':count_digits_hostname_calc,'count_digits_path':count_digits_path_calc,'count_digits_param':count_digits_param_calc,'count_letter_url':count_letter_url_calc,'count_letter_hostname':count_letter_hostname_calc,'count_letter_path':count_letter_path_calc,'count_letter_param':count_letter_param_calc,'count_tokens_hostname':tokens_hostname,'count_tokens_path':tokens_path,'count_tokens_param':tokens_param,'count_non_alpha_url':count_non_alpha_url_calc,'count_non_alpha_hostname':count_non_alpha_hostname_calc,'count_non_alpha_path':count_non_alpha_path_calc,'count_non_alpha_param':count_non_alpha_param_calc
            ,'count_periodt_url':count_periodt_url_calc,'count_periodt_hostname':count_periodt_hostname_calc,'count_periodt_path':count_periodt_path_calc,'count_periodt_param':count_periodt_param_calc,'case_changes_url':case_changes_url_calc,'case_changes_hostname':case_changes_hostname_calc,'case_changes_path':case_changes_path_calc,'case_changes_param':case_changes_param_calc,'pattern_char_url':pattern_char_url_calc,'pattern_char_hostname':pattern_char_hostname_calc,'pattern_char_path':pattern_char_path_calc,'pattern_char_param':pattern_char_param_calc,'is_tld':is_tld,'out_ip_host':out_ip_host_calc,'cisco_in_hostname':cisco_in_hostname_calc,'cisco_out_url':cisco_out_hostname_calc,'key_client':key_client_clac,'key_admin':key_admin_clac,'key_server':key_server_clac,'key_login':key_login_clac,'vowel_consonant':vowel_consonant_calc,'digit_letter':digit_letter_calc,'avg_tokens':avg_tokens_calc,'continuity_rate':continuity_rate_calc,'number_of_subdomains':number_of_subdomains_calc,'age_host':age_calc,'intented_life_span':intented_life_span_calc,'life_remaining':life_remaining_calc,'ttl_from_registration':ttl_from_registration_calc,'num_open_ports':num_open_ports_calc,'is_live':is_live_calc,'connection_speed':connection_speed_calc,'days_since_update_date':days_since_update,'days_since_first_seen':days_since_first_seen_calc,'days_since_last_seen':days_since_last_seen_calc,'average_update_frequency':average_update_frequency_calc,'registration_country':registration_country_calc,'hosting_country': hosting_country_calc,'isp':isp_calc},ignore_index=True)
            df.to_csv("prueba.csv")

inFile.seek(0, os.SEEK_END)
fileBytePos = inFile.tell()
inFile.close()

while True:

    try:

        inFile = open("pass_logs_prueba.txt", 'r')
        inFile.seek(0, os.SEEK_END)
        sizeInputFile = inFile.tell()
        print(sizeInputFile)

        # Test if the file don't increase
        if not fileBytePos == sizeInputFile:
        # Seek in the last position
            inFile.seek(fileBytePos)
            fileInMemory = inFile.read()
            # After read, the new fileBytePos
            fileBytePos = inFile.tell()
            print(fileInMemory)

            #SE PROCESAN NUEVAS LINEAS
            for match in re.finditer(pattern,str(fileInMemory)):
                print("HA MACHEADO!!!!")
                dict={"dst_ip":match["dst_ip"],"service":match["var_service"],"hostname":match["var_hostname"],"action":match["var_action"],"url":match["var_url"]}
                list.append(dict)

                #Calcular PARAMS
                hostname_url=dict["hostname"]
                path_param_url=dict["url"]
                [path_url,param_url]=split_path_param(path_param_url)
                service_url=dict["service"]
                ip_url=dict["dst_ip"] 
                url=whole_url(service_url,hostname_url,path_param_url)
                snapshots=get_snapshots(url)
                action=dict["action"]

            
                if  action=='blocked':
                        #La URL SÍ ha sido detectada como maliciosa
                        action=1
                else:
                        #La URL NO ha sido detectado como maliciosa
                        action=0

                Y.append({'label_is_malicious':action},ignore_index=True)

                #CALCULATE FEATURES ----------------------------------------------------------------------------------

                #Lexical features *********
            
                #Length features --------------
                length_url_calc=len_url(whole_url)
                length_hostname_calc=len_hostname(hostname_url)
                length_path_calc=len_path(path_url)
                length_param_calc=len_param(param_url)
                long_token_host_calc=long_token_host(hostname_url)
                long_token_path_calc=long_token_path(path_url)
                long_token_param_calc=long_token_param(param_url)
                long_token_url_calc=Long_token_URL(hostname_url,path_url,param_url)
                hostPathRatio_calc=hostPathRatio(hostname_url,path_url)
                hostParamRatio_calc=hostParamRatio(hostname_url,param_url)
                hostURLRatio_calc=hostUrlRatio(hostname_url,whole_url)
                pathUrlRatio_calc=pathUrlRatio(whole_url,path_url)
                paramUrlRatio_calc=paramUrlRatio(whole_url,param_url)

                #Counting features --------------------
                count_special_char_url_calc=count_special_char(url)
                count_special_char_hostname_calc=count_special_char(hostname_url)
                count_special_char_path_calc=count_special_char(path_url)
                count_special_char_param_calc=count_special_char(param_url)
                count_digits_url_calc=count_digits(url)
                count_digits_hostname_calc=count_digits(hostname_url)
                count_digits_path_calc=count_digits(path_url)
                count_digits_param_calc=count_digits(param_url)
                count_letter_url_calc=count_letter(url)
                count_letter_hostname_calc=count_letter(hostname_url)
                count_letter_path_calc=count_letter(path_url)
                count_letter_param_calc=count_letter(param_url)
                [tokens_hostname,tokens_path,tokens_param]=count_token(hostname_url,path_url,param_url)
                count_non_alpha_url_calc=count_nonalpha(url)
                count_non_alpha_hostname_calc=count_nonalpha(hostname_url)
                count_non_alpha_path_calc=count_nonalpha(path_url)
                count_non_alpha_param_calc=count_nonalpha(param_url)
                count_periodt_url_calc=count_periodt(url)
                count_periodt_hostname_calc=count_nonalpha(hostname_url)
                count_periodt_path_calc=count_nonalpha(path_url)
                count_periodt_param_calc=count_nonalpha(param_url)

                #Pattern Features --------------
                case_changes_url_calc=case_changes(url)
                case_changes_hostname_calc=case_changes(hostname_url)
                case_changes_path_calc=case_changes(path_url)
                case_changes_param_calc=case_changes(param_url)
                pattern_char_url_calc=pattern_char(url)
                pattern_char_hostname_calc=pattern_char(hostname_url)
                pattern_char_path_calc=pattern_char(path_url)
                pattern_char_param_calc=pattern_char(param_url)

                #Binary features----------------------
                is_tld=tld(hostname_url,url)
                out_ip_host_calc=out_ip_host(hostname_url)
                cisco_in_hostname_calc=cisco_in_hostname(hostname_url,domain_list)
                cisco_out_hostname_calc=cisco_out_url(path_param_url,domain_list)
                key_client_clac=key_client(url)
                key_admin_clac=key_admin(url)
                key_server_clac=key_server(url)
                key_login_clac=key_login(url)

                #Ratio features -------------
                vowel_consonant_calc=vowel_consonant(url)
                digit_letter_calc=digit_letter(url)
                avg_tokens_calc=avg_tokens(hostname_url,path_url,param_url)
                continuity_rate_calc=continuity_rate(url)

                #HOSTBASED FEATURES ###################################
                shodan_host=shodan_get_host(ShodanApi,ip_url)
                #Comprobar si el TLD es válido para consultar API WHOIS
                current_tld=obtain_tld(hostname_url)
                current_tld="."+str(current_tld)
                is_valid=valid_tld(current_tld,tld_list)

                #Si el hostname es una IP o el hostname tiene un tld inválido no se pueden realizar querys a whois
                if (out_ip_host(hostname_url)==True) or (is_valid==False):
                    number_of_subdomains_calc=1
                    age_calc=0
                    intented_life_span_calc=0
                    life_remaining_calc=0
                    ttl_from_registration_calc=0
                    days_since_update=0
                    registration_country_calc="Unknown"
            
                else: 
                    number_of_subdomains_calc=number_of_subdomains(ip_url,shodan_host)
                    registration_country_calc=registration_country(hostname_url)
                    age_calc=age_host(hostname_url)
                    intented_life_span_calc=intented_life_span(hostname_url)
                    life_remaining_calc=life_remaining(hostname_url)
                    ttl_from_registration_calc=ttl_from_registration(url,hostname_url)
                    days_since_update=days_since_update_date(hostname_url)

                #Resto de parámetros hostname-based que se pueden calcular aun con hostname siendo una IP
                num_open_ports_calc=num_open_ports(shodan_host)
                is_live_calc=is_live(url)
                connection_speed_calc=connection_speed(url)
                days_since_first_seen_calc=days_since_first_seen(snapshots)
                days_since_last_seen_calc=days_since_last_seen(snapshots)
                average_update_frequency_calc=average_update_frequency(snapshots)
                hosting_country_calc=hosting_country(shodan_host)
                isp_calc=isp(shodan_host)

                df=df.append({'len_url':length_url_calc,'len_hostname':length_hostname_calc,'len_path':length_path_calc,'len_param':length_param_calc,'long_token_host':long_token_host_calc,'long_token_path':long_token_path_calc,'long_token_param':long_token_param_calc,'Long_token_URL':long_token_url_calc,'hostPathRatio':hostPathRatio_calc,'hostParamRatio':hostParamRatio_calc,'hostUrlRatio':hostURLRatio_calc,'pathUrlRatio':pathUrlRatio_calc,'paramUrlRatio':paramUrlRatio,'count_special_char_url':count_special_char_url_calc,'count_special_char_hostname':count_special_char_hostname_calc,'count_special_char_path':count_special_char_hostname_calc,'count_special_char_param':count_special_char_param_calc, 'count_digits_url':count_digits_url_calc,'count_digits_hostname':count_digits_hostname_calc,'count_digits_path':count_digits_path_calc,'count_digits_param':count_digits_param_calc,'count_letter_url':count_letter_url_calc,'count_letter_hostname':count_letter_hostname_calc,'count_letter_path':count_letter_path_calc,'count_letter_param':count_letter_param_calc,'count_tokens_hostname':tokens_hostname,'count_tokens_path':tokens_path,'count_tokens_param':tokens_param,'count_non_alpha_url':count_non_alpha_url_calc,'count_non_alpha_hostname':count_non_alpha_hostname_calc,'count_non_alpha_path':count_non_alpha_path_calc,'count_non_alpha_param':count_non_alpha_param_calc
                ,'count_periodt_url':count_periodt_url_calc,'count_periodt_hostname':count_periodt_hostname_calc,'count_periodt_path':count_periodt_path_calc,'count_periodt_param':count_periodt_param_calc,'case_changes_url':case_changes_url_calc,'case_changes_hostname':case_changes_hostname_calc,'case_changes_path':case_changes_path_calc,'case_changes_param':case_changes_param_calc,'pattern_char_url':pattern_char_url_calc,'pattern_char_hostname':pattern_char_hostname_calc,'pattern_char_path':pattern_char_path_calc,'pattern_char_param':pattern_char_param_calc,'is_tld':is_tld,'out_ip_host':out_ip_host_calc,'cisco_in_hostname':cisco_in_hostname_calc,'cisco_out_url':cisco_out_hostname_calc,'key_client':key_client_clac,'key_admin':key_admin_clac,'key_server':key_server_clac,'key_login':key_login_clac,'vowel_consonant':vowel_consonant_calc,'digit_letter':digit_letter_calc,'avg_tokens':avg_tokens_calc,'continuity_rate':continuity_rate_calc,'number_of_subdomains':number_of_subdomains_calc,'age_host':age_calc,'intented_life_span':intented_life_span_calc,'life_remaining':life_remaining_calc,'ttl_from_registration':ttl_from_registration_calc,'num_open_ports':num_open_ports_calc,'is_live':is_live_calc,'connection_speed':connection_speed_calc,'days_since_update_date':days_since_update,'days_since_first_seen':days_since_first_seen_calc,'days_since_last_seen':days_since_last_seen_calc,'average_update_frequency':average_update_frequency_calc,'registration_country':registration_country_calc,'hosting_country': hosting_country_calc,'isp':isp_calc},ignore_index=True)
                df.to_csv("prueba.csv")

        time.sleep(10)

    except:
        time.sleep(10)



       
       
