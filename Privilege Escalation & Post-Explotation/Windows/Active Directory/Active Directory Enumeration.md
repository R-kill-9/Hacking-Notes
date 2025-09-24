rpcclient -U  ip -c 'enumdomusers'

pon comando revisar descripciones del usuario

for rid in $(rpcclient -U  ip -c 'enumdomusers' | grep -oP '\ [.*?\ ]' | grep '0x' | tr -d '[]');  do echo -e "\n[+] Information of RID $rid:\n"; rpcclient -U  ip -c 'queryuser $rid' | grep -E -l "username|description" ;done


tambien enumdomgroups

querygroupmem id

queryuser rid


netexec


python3 ldapdomaindump.py -u 'domain\user'-p pass 