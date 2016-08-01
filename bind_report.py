import json
import re, grp, pwd, socket

__author__ = 'speroma'

"""
[{username1:{uid: <uid>, group: <primary group>, sgroup: [1, 2, 3]}, 
 {username2:{uid: <uid>, group: <primary group>, sgroup: [1, 2, 3]}]
"""

class UsersGroupsDb(object):
    def __init__(self):
        self.consolidateDb = self.getsettings()

    def getsettings(self):
        users = []
        for user in pwd.getpwall():
            username = user[0]
            userid = pwd.getpwnam(username)[2]
            groupid = pwd.getpwnam(user[0])[3]
            groupname = grp.getgrgid(groupid)[0]
            groupsec = grp.getgrgid(groupid)[3]
            users.append({username:{'uid': userid, 'pgroup': groupname, 'sgroup': groupsec}})

        return users

class SudoCmndAlias(object):
    def __init__(self,runas,passwd,command,sp):
        self.runas = runas
        self.passwd = passwd
        self.command = command
        self.sp = sp

    def __repr__(self):
        commands = []
        for cmndAlias in self.sp.cmndAliases:
            if (cmndAlias == self.command):
                commands = self.sp.cmndAliases[cmndAlias]
                
        if (self.passwd):
            str = "(%s) %s\n" % (self.runas, self.command)
        else:
            str = "(%s) NOPASSWD: %s" % (self.runas, self.command)
        for command in commands:
            str += "\t%s\n" % command
        return str

    def matchCommand(self,command):
        if (command == self.command):
            return True
        for cmndAlias in self.sp.cmndAliases:
            if (cmndAlias == self.command):
                return self.sp.matchCmndAlias(self.sp.cmndAliases[cmndAlias],command)
        return self.sp.matchCmndAlias([self.command],command)

class SudoRuleChecker(object):
    def __init__(self,user,server,command,sp):
        self.user = user
        self.server = server
        self.command = command
        self.sp = sp

    def __repr__(self):
        return "%s %s %s" % (self.user,self.server,self.command)

    def matchUser(self,user):
        if (user == self.user):
            return True
        for userAlias in self.sp.userAliases:
            if(userAlias == self.user): 
                return self.sp.matchUserAlias(self.sp.userAliases[userAlias],user)
        return self.sp.matchUserAlias([self.user],user)

    def matchHost(self,host):
        if (host == self.server):
            return True
        for hostAlias in self.sp.hostAliases:
            if (hostAlias == self.server): 
                return self.sp.matchHostAlias(self.sp.hostAliases[hostAlias],host)
        return self.sp.matchHostAlias([self.server],host)


class SudoersParser(object):
    def parseFile(self,file):
        self.hostAliases  = {}
        self.userAliases  = {}
        self.cmndAliases  = {}
        self.rules        = []
    
        fh = open(file,"r")
        lines = fh.readlines()
        lines = self._collapseLines(lines)

        hostAliasRE = re.compile("^\s*Host_Alias")
        userAliasRE = re.compile("^\s*User_Alias")
        cmndAliasRE = re.compile("^\s*Cmnd_Alias")

        for line in lines:
            if (hostAliasRE.search(line)):
                self.hostAliases.update(self._parseAlias(line,"Host_Alias"))
                continue
            if (userAliasRE.search(line)):
                self.userAliases.update(self._parseAlias(line,"User_Alias"))
                continue
            if (cmndAliasRE.search(line)):
                self.cmndAliases.update(self._parseAlias(line,"Cmnd_Alias"))
                continue

            rule = self._parseRule(line)
            if(rule):
                self.rules.append(rule)

    def getCommands(self,user,host="localhost"):
        if (host=="localhost" or host==None):
            host=socket.gethostname()

        print "\nTesting what %s can run on %s\n" % (user,host)
        match = False
        for rule in self.rules:
            if (rule.matchUser(user) and rule.matchHost(host)):
                match = True
                for cmnd in rule.command:
                    print cmnd
        if (not match):
            print "No matches - check spelling\n"

    def canRunCommand(self,user,command,host="localhost"):
        if (host=="localhost" or host==None):
            host=socket.gethostname()
        for rule in self.rules:
            if (rule.matchUser(user) and rule.matchHost(host)):
                for cmnd in rule.command:
                    if (cmnd.matchCommand(command)):
                        print "User %s can run command %s" % (user,command)
                        return True
        print "User %s can not run command %s" % (user,command)
        return False
            
    def matchUserAlias(self,userAlias, user):
        for entry in userAlias:
            if (entry == user):
                return True
            elif (entry[0] == "%"):
                return self._userInGroup(entry[1:],user)
        return False

    def matchHostAlias(self,hostAlias,host):
        for entry in hostAlias:
            if (entry == "ALL"):
                return True
            elif (entry.find(host) == 0):
                return True
        return False

    def matchCmndAlias(self,cmndAlias,command):
        match = False
        for entry in cmndAlias:
            negate = False
            if (entry[0] == "!"):
                negate = True
                entry = entry[1:]
            if (entry.find(command) == 0):
                if(negate):
                    return False
                match = True
            if (os.path.normpath(entry) == os.path.dirname(command)):
                if (negate):
                    return False
                match = True
            if (entry == "ALL"):
                match = True
        return match
                
    def _userInGroup(self,group,user):
        try:
            (gr_name, gr_passwd, gr_gid, gr_mem) = grp.getgrnam(group)
        except KeyError:
            return False
        if(user in gr_mem):
            return True
    
    def _parseAlias(self,line,marker):
        res = {}
    
        aliasRE = re.compile("\s*%s\s*(\S+)\s*=\s*((\S+,?\s*)+)" % marker)
        m = aliasRE.search(line)
        if (m):
            alias = str(m.group(1))
            nodes = str(m.group(2)).split(",")
            nodes = [ node.strip() for node in nodes ]
            res[alias] = nodes

        return res

    def _parseRule(self,line):
        ruleRE = re.compile("\s*(\S+)\s*(\S+)\s*=\s*(.*)")
        runasRE = re.compile("^\s*\((\S+)\)(.*)")
        m = ruleRE.search(line)
        if (m):
            user = str(m.group(1))
            host = str(m.group(2))
            parsedCommands = []
            
            cmnds = str(m.group(3)).split(",")
            cmnds = [ cmnd.strip() for cmnd in cmnds ]
            for cmnd in cmnds:
                unparsed = cmnd
                m = runasRE.search(unparsed)
                if (m):
                    runas = str(m.group(1))
                    unparsed = str(m.group(2))
                else:
                    runas = "ANY"
                pos = unparsed.find("NOPASSWD:")
                if (pos > -1):
                    passwd = False
                    unparsed = unparsed[pos+len("NOPASSWD:"):]
                else:
                    passwd = True
                unparsed = unparsed.strip()

                parsedCommands.append(SudoCmndAlias(runas,passwd,unparsed,self))
            
            return SudoRuleChecker(user,host,parsedCommands,self)

    def _collapseLines(self,lines):
        response = []
        currentline = ""
        
        for line in lines:
            if (line.rstrip()[-1:] == "\\"):
                currentline += line.rstrip()[:-1]
            else:
                currentline += line
                response.append(currentline)
                currentline = ""

        return response

def main():
    sparser = SudoersParser()
    sparser.parseFile('../../Python/etc/sudoers')
    #user = 'speroma'
    #sp.getCommands(user,None)

    getusergrp = UsersGroupsDb()
    
    # Users
    for entry in getusergrp.consolidateDb:
        for user in entry.iterkeys():
            sparser.getCommands(user,None)

    # Groups
    for entry in getusergrp.consolidateDb:
        for values in entry.itervalues():
            for key, value in values.iteritems():
                if 'pgroup' in key:
                    sparser.getCommands("%" + value,None)

if(__name__ == "__main__"):
    main()
