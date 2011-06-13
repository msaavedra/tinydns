
import re
import os
import subprocess

from cross_platform import files

def make(tinydns_root):
    """Recompile the tinydns data file.
    
    This will cause all DNS changes to go live.
    """
    cwd = os.getcwd()
    os.chdir(tinydns_root)
    return_code = subprocess.call('tinydns-data')
    if return_code > 0:
        raise Exception('tinydns-data error: %s' % return_code)
    os.chdir(cwd)

class AuthoritativeDNS(object):
    """Representation of the entire authoritative DNS data served by tinydns.
    
    This object should contain one or more sections of DNS records.
    """
    def __init__(self):
        self.sections = []
    
    def read(self, *file_names):
        self.sections = []
        for file_name in file_names:
            section = Section(file_name)
            section.read()
            self.sections.append(section)
    
    def __iter__(self):
        return iter(self.sections)
    
    def __str__(self):
        return '\n'.join(str(section) for section in self.sections)
    
    def append(self, section):
        """Add a section after the last current section.
        """
        self.sections.append(section)
    
    def prepend(self, section):
        """Add a section before the first current section.
        """
        self.sections.insert(0, section)
    
    def search(self, field, regex):
        """Returns the records where a field matches the supplied regex.
        
        The regular expression should be a string, not compiled by the
        re module from the python standard library.
        """
        results = []
        for section in self.sections:
            results.extend(section.search(field, regex))
    
    def merge(self, tinydns_root):
        """Replace tinydns's data with the data in this object.
        """
        data_path = os.path.join(tinydns_root, 'data')
        data = '\n'.join(str(f) for f in self.sections)
        files.save(data, data_path, safe=True)


class Section(object):
    """A group of DNS records that belong together.
    
    These can be read from and written to a file, or created dynamically.
    """
    def __init__(self, file_name=''):
        self.file_name = file_name
        self.records = []
    
    def __str__(self):
        return ''.join(str(record) for record in self.records)
    
    def add(self, *lines):
        """Add a data line to the section.
        """
        self.records.extend(lines)
    
    def read(self):
        """Read data lines from a file.
        """
        for line in files.yield_lines(self.file_name):
            marker = line[0]
            fields = line[1:].split(':')
            cls = MARKER_CLASSES[marker]
            self.records.append(cls.create(marker, fields))
    
    def write(self):
        """Write all the data lines in this section to a file.
        """
        files.save(str(self), self.file_name, safe=True)
    
    def search(self, field, regex):
        """Returns the data lines where a field matches the supplied regex.
        
        The regular expression should be a string, not compiled by the
        re module from the python standard library.
        """
        return [rec for rec in self.records if rec.matches(field, regex)]


class _DataLine(object):
    """A base class for all lines in the tinydns data file.
    
    See http://cr.yp.to/djbdns/tinydns-data.html for a complete description
    of what all the data lines and fields do.
    """
    markers = ()
    field_names = ()
    
    def set_fields(self, field_dict):
        """Set field values based on data in the supplied dictionary.
        """
        self.fields = []
        for name in self.field_names:
            if name in field_dict:
                self.fields.append(field_dict[name])
            else:
                self.fields.append('')
    
    def __setitem__(self, name, value):
        self.fields[self.field_names.index(name)] = value
    
    def __getitem__(self, name):
        return self.fields[self.field_names.index(name)]
    
    def __str__(self):
        line = self.marker + ':'.join(self.fields)
        while line.endswith(':'):
            line = line[:-1]
        return line + '\n'
    
    def matches(self, field, regex):
        """Returns True if the value of the field matches the regex.
        
        The regular expression should be a string, not compiled by the
        re module from the python standard library.
        """
        if field not in self.field_names:
            return False
        if re.compile(regex).search(self[field]):
            return True
        else:
            return False
    
    @classmethod
    def create(cls, marker, fields):
        """Create an instance of the class with fields from the given line.
        """
        kwargs = dict(map(_process_fields, cls.field_names, fields))
        return cls(**kwargs)


class Location(_DataLine):
    """Allows tinydns to associate a name with a client IP address prefix.
    
    The name can be used as a field in other data lines, which will cause
    tinydns to serve that data only to matching clients.
    """
    markers = ('%',)
    field_names = ('name', 'ip_prefix')
    
    def __init__(self, name, ip_prefix):
        self.marker = '%'
        self.set_fields(vars())

############ Tinydns data lines. See the tinydns docs for more info ###########

class NameServer(_DataLine):
    """Specifies an authoritative name server for the given domain.
    """
    markers = ('.', '&')
    field_names = ('domain', 'ip', 'server_name', 'ttl', 'stamp', 'location')
    
    def __init__(self, domain, server_name, ip='', soa=True,
            ttl='', stamp='', location=''):
        if soa:
            self.marker = '.'
        else:
            self.marker = '&'
        self.set_fields(vars())
    
    @classmethod
    def create(cls, marker, fields):
        kwargs = dict(map(_process_fields, cls.field_names, fields))
        if marker == '&':
            kwargs['soa'] = True
        return cls(**kwargs)

class Alias(_DataLine):
    """Specifies an domain name for an IP address.
    """
    markers = ('=', '+', '-')
    field_names = ('host_name', 'ip', 'ttl', 'stamp', 'location')
    
    def __init__(self, host_name, ip, ptr=True, disabled=False,
            ttl='', stamp='', location=''):
        if disabled:
            self.marker = '-'
        elif ptr:
            self.marker = '='
        else:
            self.marker = '+'
        self.set_fields(vars())
    
    @classmethod
    def create(cls, marker, fields):
        kwargs = dict(map(_process_fields, cls.field_names, fields))
        if marker == '-':
            kwargs['disabled'] = True
        elif marker == '+':
            kwargs['ptr'] = False
        return cls(**kwargs)

class MailExchange(_DataLine):
    """Specifies a mail server to use for a domain.
    """
    markers = ('@',)
    field_names = ('domain', 'ip', 'server_name', 'distance', 
        'ttl', 'stamp', 'location')
    
    def __init__(self, domain, server_name,  ip, distance=0,
            ttl='', stamp='', location=''):
        self.marker = '@'
        self.set_fields(vars())

class Text(_DataLine):
    """Specifies text that can be served by tinydns.
    """
    markers = ("'",)
    field_names = ('host_name', 'text', 'ttl', 'stamp', 'location')
    
    def __init__(self, host_name, text, ttl='', stamp='', location=''):
        self.marker = "'"
        self.set_fields(vars())

class Pointer(_DataLine):
    """Specifies a reverse lookup record.
    """
    markers = ('^',)
    field_names = ('reverse_name', 'host_name', 'ttl', 'stamp', 'location')
    
    def __init__(self, reverse_name, host_name, ttl='', stamp='', location=''):
        self.marker = '^'
        self.set_fields(vars())

class Cname(_DataLine):
    """Specifies a name that refers back to a target alias.
    """
    markers = ('C')
    field_names = ('host_name', 'target', 'ttl', 'stamp', 'location')
    
    def __init__(self, host_name, target, ttl='', stamp='', location=''):
        self.marker = 'C'
        self.set_fields(vars())
    
class Soa(_DataLine):
    """Specifies a Statement of Authority for a domain.
    """
    markers = ('Z',)
    field_names = ('host_name', 'name_server', 'contact', 'serial',
        'refresh_time', 'retry_time', 'expire_time', 'min_time',
        'ttl', 'stamp', 'location')
    
    def __init__(self, host_name, name_server, contact, serial='',
            refresh_time='', retry_time='', expire_time='', min_time='',
            ttl='', stamp='', location=''):
        self.marker = 'Z'
        self.set_fields(vars())
    
class Generic(_DataLine):
    """Specifies a generic record.
    
    This can be used to implement new record types that are not supported
    directly by tinydns.
    """
    markers = (':',)
    field_names = ('host_name', 'record_type', 'data',
        'ttl', 'stamp', 'location')
    
    def __init__(self, host_name, record_type, data,
            ttl='', stamp='', location=''):
        self.marker = ':'
        self.set_fields(vars())
    
class Comment(_DataLine):
    """Specifies a line in the data file that is for information only.
    """
    markers = ('#',)
    field_names = ('text',)
    
    def __init__(self, text):
        self.marker = '#'
        self.set_fields(vars())
    
    def __str__(self):
        return self.marker + ':'.join(self.fields) + '\n'

class Blank(_DataLine):
    """An empty line, used only to space things out for easier reading.
    """
    markers = ('',)
    field_names = ('Null',)
    
    def __init__(self, *args, **kwargs):
        self.fields = ['']
        self.marker = ''

##### Non-public code. Do not use. It is subject to change without warning. ####

def _process_fields(name, value):
    """A convenience function to turn None values into empty strings.
    """
    if value == None:
        value = ''
    return name, value

def _map_marker_classes(classes):
    """Return a dictionary that maps markers to the appropriate data line class.
    """
    markers = {}
    for cls in classes:
        if (type(cls) == type(_DataLine)) and issubclass(cls, _DataLine):
            for marker in cls.markers:
                if markers.has_key(marker):
                    raise Exception('Duplicate marker %s' % marker)
                markers[marker] = cls
    return markers

MARKER_CLASSES = _map_marker_classes(globals().values())

