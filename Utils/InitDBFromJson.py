import MySQLdb
import json

unix_socket = None
# unix_socket = '/opt/var/run/mysqld.sock'
username = 'root'
password = ''
mapfile = '../Hostnames.json'

if unix_socket is not None:
    conn = MySQLdb.connect('localhost', username, password, unix_socket=unix_socket)
else:
    conn = MySQLdb.connect('localhost', username, password)
print "connected"
cursor = conn.cursor()
print "cursor returned"

f_map_json = open(mapfile)
f_map = json.load(f_map_json)
f_map_json.close()


def create_db():
    try:
        cursor.execute('Create Database HostDB')
    except MySQLdb.ProgrammingError:
        cursor.execute('Drop Database HostDB')
        cursor.execute('Create Database HostDB')


def create_table():
    cursor.execute('Create Table HostDB.config ('
                   'config varchar(256) NOT NULL, '
                   'int_value integer, '
                   'string_value varchar(256),'
                   'description varchar(512),'
                   'PRIMARY KEY (config)'
                   ')')

    cursor.execute('Create Table HostDB.Hosts ('
                   'id int NOT NULL AUTO_INCREMENT,'
                   'name varchar(256) NOT NULL,'
                   'ip_last varchar(32),'
                   'mac_last char(17),'
                   'status int NOT NULL DEFAULT 0,'
                   'PRIMARY KEY (id)'
                   ')')

    cursor.execute('Create Table HostDB.DNS ('
                   'id int NOT NULL AUTO_INCREMENT,'
                   'name varchar(256) NOT NULL,'
                   'username varchar(256) DEFAULT \'\','
                   'password varchar(256) DEFAULT \'\','
                   'method varchar(8) NOT NULL,'
                   'url varchar(512) NOT NULL,'
                   'headers varchar(512),'
                   'http_auth varchar(512) DEFAULT \'\','
                   'content varchar(1024),'
                   'timeout int NOT NULL DEFAULT 0,'
                   'PRIMARY KEY (id)'
                   ')')

    cursor.execute('Create Table HostDB.Script ('
                   'id int NOT NULL AUTO_INCREMENT,'
                   'name varchar(256) NOT NULL,'
                   'command varchar(256) NOT NULL,'
                   'timeout int NOT NULL DEFAULT 0,'
                   'PRIMARY KEY (id)'
                   ')')

    cursor.execute('Create Table HostDB.HostDNS ('
                   'id_host int NOT NULL,'
                   'id_dns int NOT NULL,'
                   'hostname varchar(256) NOT NULL,'
                   'CONSTRAINT pk_RelateHostDns PRIMARY KEY (id_host, id_dns),'
                   'FOREIGN KEY (id_host) REFERENCES HostDB.Hosts(id) on delete cascade,'
                   'FOREIGN KEY (id_dns) REFERENCES HostDB.DNS(id) on delete cascade'
                   ')')

    cursor.execute('Create Table HostDB.HostScript ('
                   'id_host int NOT NULL,'
                   'id_script int NOT NULL,'
                   'param varchar(512),'
                   'CONSTRAINT pk_RelateHostScript PRIMARY KEY (id_host, id_script),'
                   'FOREIGN KEY (id_host) REFERENCES HostDB.Hosts(id) on delete cascade,'
                   'FOREIGN KEY (id_script) REFERENCES HostDB.Script(id) on delete cascade'
                   ')')

    cursor.execute('Create Table HostDB.HostValidate ('
                   'id_host int NOT NULL,'
                   'validate_type varchar(16) NOT NULL,'
                   'validate_value varchar(256),'
                   'FOREIGN KEY (id_host) REFERENCES HostDB.Hosts(id) on delete cascade'
                   ')')


def sql_insert_table(tbl_name, dict_kv_pair):
    n_pair = len(dict_kv_pair)
    formats = ("%s, " * n_pair)[:-2]
    sql_key = []
    sql_value = []
    for k, v in dict_kv_pair.items():
        sql_key.append(k)

        v_formatted = 'NULL'
        if v is None:
            pass
        elif isinstance(v, basestring):
            v_formatted = "'%s'" % v
        elif isinstance(v, int):
            v_formatted = str(v)
        else:
            v_formatted = "'%s'" % json.dumps(v)
        sql_value.append(v_formatted)

    sql_key = tuple(sql_key)
    sql_value = tuple(sql_value)

    sql = "INSERT %s (%s) VALUES (%s)" % (tbl_name, formats % sql_key, formats % sql_value)
    return sql


def insert_modules():
    for host in f_map["hostmap"]:
        cursor.execute(sql_insert_table("HostDB.Hosts", {"name": host}))

    for dns, values in f_map["dyndnsserver"].items():
        cursor.execute(sql_insert_table("HostDB.DNS", {
            "name": dns,
            "username": values["username"],
            "password": values["password"],
            "method": values["method"],
            "url": values["URL"],
            "headers": values["headers"],
            "http_auth": values["auth"],
            "content": values["content"],
            "timeout": values["timeout"],
        }))

    for script, values in f_map["scripts"].items():
        cursor.execute(sql_insert_table("HostDB.Script", {
            "name": script,
            "command": values["command"],
            "timeout": values["timeout"],
        }))

    conn.commit()


def insert_relations():
    cursor.execute("SELECT name, id FROM HostDB.DNS")
    dnss = dict(cursor.fetchall())
    cursor.execute("SELECT name, id FROM HostDB.Script")
    scripts = dict(cursor.fetchall())
    cursor.execute("SELECT name, id FROM HostDB.Hosts")
    hosts = dict(cursor.fetchall())

    for host, values in f_map["hostmap"].items():
        if "DNS" in values:
            for dns in values["DNS"]:
                cursor.execute(sql_insert_table("HostDB.HostDNS", {
                    "id_host": hosts[host],
                    "id_dns": dnss[dns["Profile"]],
                    "hostname": dns["Hostname"],
                }))

        if "Script" in values:
            for script in values["Script"]:
                cursor.execute(sql_insert_table("HostDB.HostScript", {
                    "id_host": hosts[host],
                    "id_script": scripts[script["Profile"]],
                    "param": script["Param"],
                }))

        if "Validate" in values:
            for validate, validate_values in values["Validate"].items():
                for value in validate_values:
                    cursor.execute(sql_insert_table("HostDB.HostValidate", {
                        "id_host": hosts[host],
                        "validate_type": validate,
                        "validate_value": value,
                    }))

    conn.commit()


create_db()
print "database created"
create_table()
insert_modules()
insert_relations()

conn.close()

