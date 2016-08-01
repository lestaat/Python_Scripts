__author__ = 'matias speroni'

csv = """David,Rudd;60050;9%;01 March-31 March
Ryan,Chen;120000;10%;01 March-31 March"""

class EnumTaxes(object):
    base_taxes = (3572, 37000, 0.325)
    upper_taxes = (17547, 80000, 0.370)
    btaxe = 37000
    mtaxe = 80000
    utaxe = 18000
            
def input_format(csv):
    l = csv.split('\n')

    dic = {}

    for i in l:
	attr = {}
        out = i.split(';')
	attr['pay period'] = out[3]
	attr['gross income'] = round(int(out[1]) / 12, 3)
	if out[1] > EnumTaxes.btaxe or out[1] <= EnumTaxes.mtaxe:
            tx1 = EnumTaxes.base_taxes[0]
            tx2 = EnumTaxes.base_taxes[1]
            tx3 = EnumTaxes.base_taxes[2]
	elif out[1] > EnumTaxes-mtaxe or out[1] <= EnumTaxes.utaxe:
            tx1 = EnumTaxes.upper_taxes[0]
            tx2 = EnumTaxes.upper_taxes[1]
            tx3 = EnumTaxes.upper_taxes[2]
	attr['income tax'] = round((tx1 + (int(out[1]) - tx2 ) * tx3 )/ 12)
	attr['net income'] = round(float(out[1]) / 12) - round((tx1 + (int(out[1]) - tx2 ) * tx3 )/ 12)
	attr['super'] = round(float(out[1]) / 12 * 0.09)
	dic[out[0]] = attr
    return dic

output = input_format(csv)

title = None

for key, val in output.items():
    value = ', '.join([str(x) for x in val.values()])
    if not title:
	title = ', '.join([x for x in val.keys()])
        print "name %s" %  title

    print "%s %s" %  (key, value)
