#!/usr/bin/python3 

import csv
import json
import requests


url = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
outfile = 'enterprise-attack-sro.csv'

print("Fetching latest enterprise-attack.json ...")
d = requests.get(url)
assert (d.status_code==200),"Failure fetching url"

print("Parsing file ...")
j = d.json()
assert ('spec_version' in j), "Failure reading version info in JSON file"
assert ('objects' in j), "Failure reading objects in JSON file"
assert (j['spec_version'] == '2.0'), "Unsupported STIX version"

o = {}	# dict objects
for i in j['objects']:
	assert ('type' in i), f"type information is missing in entry {i}"
	assert ('id' in i), f"id field is missing in entry {i}"

	# skip revoked or deprecated items
	if ('revoked' in i and i['revoked']==True) or ('x_mitre_deprecated' in i and i['x_mitre_deprecated']==True):
		continue

	id = i['id']
	t = i['type']

	if t not in o: o[t] = {}
	o[t][id] = i

print("Generating list of tactics ...")

## Generate a list of tactics
#tactics = {}
#for t in o['x-mitre-tactic']:
#	short_name = o['x-mitre-tactic'][t]["x_mitre_shortname"]
#	name = o['x-mitre-tactic'][t]["name"]
#	id = o['x-mitre-tactic'][t]['external_references'][0]["external_id"]
#	url = o['x-mitre-tactic'][t]['external_references'][0]["url"]
#
#	tactics[short_name] = name

## minature markdown
import re
def minimd(s,fmt="text"):

	code = re.compile('<code>(?P<codeblock>.*?)</code>')

	bold = re.compile('\*\*(.*?)\*\*')
	link = re.compile('\[([^[]*?)\]\((.*?)\)')
	header = re.compile('(?:^|\n)#+([^\n]*)')

	if fmt=="html":
		s = code.sub(lambda x: '<code>{}</code>'.format(x.group('codeblock').replace('<','&lt;')), s)
		s = bold.sub(r'<b>\1</b>',s)
		s = link.sub(r'<a href="\2">\1</a>', s)
		s = header.sub(r'<b><u>\1</u></b><br/>',s)

		# rewrite links to mitre page to this one (mitre to internal link)
		mtil = re.compile('"https://attack.mitre.org/techniques/(?P<technique>.*?)"')
		s = mtil.sub(lambda x: '"#{}"'.format(x.group('technique').replace('/','.')), s)

		s = s.replace('\n','<br/>')

	elif fmt=="text":
		# tidy headers
		s = header.sub(r'# \1 #\n',s)

		# neaten code
		s = code.sub(lambda x: '`{}`'.format(x.group('codeblock')), s)

		# rewrite links to mitre page to plaintext
		mtil = re.compile('https://attack.mitre.org/(techniques|tactics|software)/(?P<technique>[^\])"]+)')
		s = mtil.sub(lambda x: '{}'.format(x.group('technique').replace('/','.')), s)

		# remove <br>
		s = s.replace('<br>','\n')


	return s

print("Generating list of techniques ...")
# Generate a list of reationships
rs_d = {}
for rs_id in o["relationship"]:
	rs = o["relationship"][rs_id]
	source_ref = rs["source_ref"]
	target_ref = rs["target_ref"]
	relationship_type = rs["relationship_type"]
	description = rs["description"] if "description" in rs else ""
	description = minimd(description)
	rs_d[rs_id] = (source_ref, target_ref, relationship_type, description)

print("Generating CSV file ...")
with open(outfile,'w',newline='\n') as out:
	writer = csv.DictWriter(out, ['id', 'source_ref', 'target_ref', 'relationship type', 'description'], quoting=csv.QUOTE_ALL)
	writer.writeheader()

	for rs_id in sorted(rs_d.keys()):
		rs = rs_d[rs_id]
		source_ref = rs[0]
		tatget_ref = rs[1]
		relationship_type = rs[2]
		description = rs[3]

		writer.writerow({
			'id': rs_id,
			'source_ref':source_ref,
			'target_ref':target_ref,
			'relationship type':relationship_type,
			'description':description})
