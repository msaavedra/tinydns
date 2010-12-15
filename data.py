
import re
import os
import subprocess

from cross_platform import files

def make(tinydns_root):
    cwd = os.getcwd()
    os.chdir(tinydns_root)
    return_code = subprocess.call('tinydns-data')
    if return_code > 0:
        raise Exception('tinydns-data error: %s' % return_code)
    os.chdir(cwd)

class Authority(object):
    """Representation of the authoritative DNS data served by tinydns.
    """
    def __init__(self):
        self.sections = []
    
    def read(self, directory, prefix=None, suffix=None):
        self.sections = []
        for file_name in os.listdir(directory):
            if file_name.endswith('/'):
                continue
            if prefix:
                if not file_name.startswith(prefix):
                    continue
            if suffix:
                if not file_name.endswith(suffix):
                    continue
            file_path = os.path.join(directory, file_name)
            section = Section(file_path)
            section.read()
            self.sections.append(section)
    
    def read_names(self, *file_names):
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
        self.sections.append(section)
    
    def prepend(self, section):
        self.sections.insert(0, section)
    
    def search(self, field, regex):
        results = []
        for section in self.sections:
            results.extend(section.search(field, regex))
    
    def write(self):
        for section in self.sections:
            section.write()
    
    def merge(self, tinydns_root):
        data_path = os.path.join(tinydns_root, 'data')
        data = '\n'.join(str(f) for f in self.sections)
        files.save(data, data_path, safe=True)

class Section(object):
    
    def __init__(self, file_name=''):
        self.file_name = file_name
        if not file_name:
            self.read = self.do_nothing
            self.write = self.do_nothing
        self.records = []
    
    def __str__(self):
        return ''.join(str(record) for record in self.records)
    
    def add(self, *lines):
        self.records.extend(lines)
    
    def read(self):
        for line in files.yield_lines(self.file_name):
            line = line.strip()
            marker = line[:1]
            fields = line[1:].split(':')
            cls = MARKER_CLASSES[marker]
            self.records.append(cls.create(marker, fields))
    
    def write(self):
        files.save(str(self), self.file_name, safe=True)
    
    def search(self, field, regex):
        return [rec for rec in self.records if rec.matches(field, regex)]
    
    def do_nothing(*args, **kwargs):
        return None

class _DataLine(object):
    
    markers = ()
    field_names = ()
    
    def set_fields(self, field_dict):
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
        if re.compile(regex).search(self[field]):
            return True
        else:
            return False
    
    @classmethod
    def create(cls, marker, fields):
        kwargs = dict(map(process_fields, cls.field_names, fields))
        return cls(**kwargs)

class Location(_DataLine):
    
    markers = ('%',)
    field_names = ('name', 'ip_prefix')
    
    def __init__(self, name, ip_prefix):
        self.marker = '%'
        self.set_fields(vars())

class NameServer(_DataLine):
    
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
        kwargs = dict(map(process_fields, cls.field_names, fields))
        if marker == '&':
            kwargs['soa'] = True
        return cls(**kwargs)

class Alias(_DataLine):
    
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
        kwargs = dict(map(process_fields, cls.field_names, fields))
        if marker == '-':
            kwargs['disabled'] = True
        elif marker == '+':
            kwargs['ptr'] = False
        return cls(**kwargs)

class MailExchange(_DataLine):
    
    markers = ('@',)
    field_names = ('domain', 'ip', 'server_name', 'distance', 
        'ttl', 'stamp', 'location')
    
    def __init__(self, domain, server_name,  ip, distance=0,
            ttl='', stamp='', location=''):
        self.marker = '@'
        self.set_fields(vars())

class Text(_DataLine):
    
    markers = ("'",)
    field_names = ('host_name', 'text', 'ttl', 'stamp', 'location')
    
    def __init__(self, host_name, text, ttl='', stamp='', location=''):
        self.marker = "'"
        self.set_fields(vars())

class Pointer(_DataLine):
    
    markers = ('^',)
    field_names = ('reverse_name', 'host_name', 'ttl', 'stamp', 'location')
    
    def __init__(self, reverse_name, host_name, ttl='', stamp='', location=''):
        self.marker = '^'
        self.set_fields(vars())

class Cname(_DataLine):
    
    markers = ('C')
    field_names = ('host_name', 'target', 'ttl', 'stamp', 'location')
    
    def __init__(self, host_name, target, ttl='', stamp='', location=''):
        self.marker = 'C'
        self.set_fields(vars())
    
class Soa(_DataLine):
    
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
    
    markers = (':',)
    field_names = ('host_name', 'record_type', 'data',
        'ttl', 'stamp', 'location')
    
    def __init__(self, host_name, record_type, data,
            ttl='', stamp='', location=''):
        self.marker = ':'
        self.set_fields(vars())
    
class Comment(_DataLine):
    
    markers = ('#',)
    field_names = ('text',)
    
    def __init__(self, text):
        self.marker = '#'
        self.set_fields(vars())
    
    def __str__(self):
        return self.marker + ':'.join(self.fields) + '\n'

class Blank(_DataLine):
    
    markers = ('',)
    field_names = ('Null',)
    
    def __init__(self, *args, **kwargs):
        self.fields = ['']
        self.marker = ''

def process_fields(name, value):
    if value == None:
        value = ''
    return name, value

def map_marker_classes(classes):
    markers = {}
    for obj in classes:
        if (type(obj) == type(_DataLine)) and issubclass(obj, _DataLine):
            for marker in obj.markers:
                if markers.has_key(marker):
                    raise Exception('Duplicate marker %s' % marker)
                markers[marker] = obj
    return markers

MARKER_CLASSES = map_marker_classes(globals().values())

