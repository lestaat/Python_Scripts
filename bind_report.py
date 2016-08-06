import csv, datetime, argparse, logging
import sys, os, re, grp, pwd, socket

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

            sgroupvld = []
            for sgroup in grp.getgrall():
                if username in sgroup[3]:
                    sgroupvld.append(sgroup[0])

            users.append({username: {'uid': userid, 'pgroup': groupname, 'sgroup': sgroupvld}})

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
            str = "(%s) %s" % (self.runas, self.command)
        else:
            str = "(%s) NOPASSWD: %s" % (self.runas, self.command)
        for command in commands:
            str += "\t%s" % command
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
    def parseFile(self, file, log):
        self.hostAliases  = {}
        self.userAliases  = {}
        self.cmndAliases  = {}
        self.rules        = []

        try:
            with open(file) as f:
                lines = f.readlines()
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

        except IOError as e:
            log.error("FAILED TO OPEN FILE:  %s ERROR: %s", file, e)

    def getCommands(self, user, host, type):

        match = False
        ret = []
        for rule in self.rules:
            if (rule.matchUser(user) and rule.matchHost(host)):
                match = True
                for cmnd in rule.command:
                    attr = {}
                    if type == "user":
                        attr['user'] = user
                    else:
                        attr['group'] = user
                    attr['cmnd'] = cmnd
                    ret.append(attr)
        return ret

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
        if (user in gr_mem):
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

class FormatOutput(object):
    def __init__(self, host_data, sudoers, logger, workdir):
        self.host = host_data
        self.sudoers = sudoers
        self.log = logger
        self.workdir = workdir
        self.FormatSudoers = self.Sudoersvalidation()
        self.FormatUserGroup = self.Userdbout()

    def Sudoersvalidation(self):
        sparser = SudoersParser()
        sparser.parseFile(self.sudoers, self.log)

        getusergrp = UsersGroupsDb()

        for entry in getusergrp.consolidateDb:
            l1 = []
            for user, values in entry.iteritems():
                r = sparser.getCommands(user, self.host, type='user')
                if r:
                    for r1 in r:
                        l1.append(r1["user"])
                        l1.append(r1["cmnd"])
                    csv_wr(l1, self.workdir, 'sudoers_users')
                for key, value in values.iteritems():
                    l2 = []
                    if "pgroup" in key:
                        r = sparser.getCommands("%" + value, self.host, None)
                        if r:
                            for r1 in r:
                                l2.append(user)
                                l2.append(r1["group"])
                                l2.append(r1["cmnd"])
                            csv_wr(l2, self.workdir, 'sudoers_groups')

    def Userdbout(self):
        getusergrp = UsersGroupsDb()

        rlist = []
        for entry in getusergrp.consolidateDb:
            for user in entry.iterkeys():
                lst = []
                lst.append(user)
                lst.append(entry[user]["pgroup"])
                lst.append(entry[user]["sgroup"])
                rlist.append(lst)
                csv_wr(lst, self.workdir, 'passwd')


def csv_wr(feeder, workdir, type='passwd'):
    os.chdir(workdir)
    mode = 'a'
    output = "output." + type + "." + str(datetime.date.today()) + ".csv"
    wr = csv.writer(open(output, mode), quoting=csv.QUOTE_ALL)
    wr.writerow(feeder)

def setup_logger(logger_name, log_file, level):
    logger = logging.getLogger(logger_name)
    formatter = logging.Formatter('%(levelname)s %(asctime)s :: %(message)s')
    fileHandler = logging.FileHandler(log_file, mode='a')
    fileHandler.setFormatter(formatter)
    streamHandler = logging.StreamHandler()
    streamHandler.setFormatter(formatter)

    level = logging.ERROR

    logger.setLevel(level)
    logger.addHandler(fileHandler)
    logger.addHandler(streamHandler)

def usage():
    print "Usage:"
    print ('%s -w <workdir> -s <sudoers file>' % sys.argv[0])
    print "Example:"
    print ('%s -w . -s /etc/sudoers' % sys.argv[0])
    sys.exit(2)

def main():
    host = socket.gethostname()

    parser = argparse.ArgumentParser(description='BIND Servers user privileges')
    parser.add_argument('--workdir', '-w', action="store", dest="workdir", help="Working directory")
    parser.add_argument('--sudoers', '-s', action="store", dest="sudoers", help="Sudoers file location")
    args = parser.parse_args()

    if args.workdir and args.sudoers:
        workdir = args.workdir
        sudoers = args.sudoers

        setup_logger('error', args.workdir + '/bind_report.log', 'error')
        logger = logging.getLogger('error')

        # Call Parser
        FormatOutput(host, sudoers, logger, workdir)

    else:
        usage()

if(__name__ == "__main__"):
    main()
