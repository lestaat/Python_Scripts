def find_dup(list):
    l = list.split(' ')
    dic = {}
    for elem in l:
        if elem in dic:
            dic[elem] += 1
        else:
            dic[elem] = 1
    return dic
    
list = "red green red yellow white red green"
find_dup(list)

