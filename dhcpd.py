
import time

from cross_platform import files

class Leases(object):
    
    def __init__(self, file_name):
        self.leases = []
        current_lease = None
        for line in files.yield_lines(file_name):
            line = line.strip()
            if line.startswith('#') or line == '':
                continue
            elif line.startswith('lease ') and current_lease == None:
                current_lease = Lease(line)
            elif line.startswith('}') and current_lease != None:
                self.leases.append(current_lease)
                current_lease = None
            elif current_lease != None:
                current_lease.add_line(line)
            else:
                continue
        self.leases.sort()
        self.leases.reverse()
    
    def has_key(self, mac):
        match = False
        for lease in self.leases:
            if lease.mac == mac:
                match = True
                break
        return match
    
    def __getitem__(self, mac):
        for lease in self.leases:
            if lease.mac == mac:
                return lease
        raise KeyError('MAC %s not found in leases.' % mac)
    
    def __iter__(self):
        return iter(self.leases)

class Lease(object):
    
    def __init__(self, line):
        self.ip = line.split()[1]
        self.mac = None
        self.expiration = None
        self.host_name = None
    
    def __cmp__(self, other):
        """The lease that compares highest is the one with that expires last.
        """
        if other == None:
            return 1
        return cmp(self.expiration, other.expiration)
    
    def add_line(self, line):
        fields = line[:-1].split() #Get rid of trailing semicolon before split.
        if fields[0] == 'ends':
            timestamp = '%s %s' % (fields[2], fields[3])
            self.expiration = time.mktime(
                time.strptime(timestamp, '%Y/%m/%d %H:%M:%S')
                )
        elif fields[0:2] == ['hardware', 'ethernet']:
            self.mac = fields[2]
        elif fields[0] == 'client-hostname':
            self.set_host_name(fields[1])
    
    def set_host_name(self, host_name):
        for character in ('"', "'"):
            host_name = host_name.replace(character, '')
        for character in ('/', '\\', '_', ' '):
            host_name = host_name.replace(character, '-')
        while host_name.startswith('-'):
            host_name = host_name[1:]
        if host_name == '':
            return
        self.host_name = host_name.lower()

