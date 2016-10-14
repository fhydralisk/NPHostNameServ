import MySQLdb
import json


class DBException(Exception):
    pass


class Model(object):
    KEYS = []
    PRIMARY_KEY = None
    DB_OBJ = None

    def __init__(self):
        self.data = {}

    def insert(self):
        pass

    def delete(self):
        pass

    def update(self):
        pass

    def put(self):
        pass

    def set_data(self, key, value):
        pass

    @classmethod
    def is_primary_key(cls, key):
        pass

    @classmethod
    def get_models(cls, dict_filter):
        pass


class DB(object):
    DB_NAME = None

    def __init__(self, hostname='', user='root', password=None, unix_socket=None):
        self.hostname = hostname
        self.user = user
        self.password = password
        self.unixSocket = unix_socket
        self.conn = None
        self.cursor = None

    def connect(self):
        if self.conn is not None:
            self.conn.close()

        kwargs = {
            "host": self.hostname,
            "user": self.user,
        }
        if self.password:
            kwargs["passwd"] = self.password

        if self.unixSocket:
            kwargs["unix_socket"] = self.unixSocket

        if self.__class__.DB_NAME:
            kwargs["db"] = self.__class__.DB_NAME

        self.conn = MySQLdb.connect(**kwargs)
        self.cursor = self.conn.cursor()

    def disconnect(self):
        if self.conn:
            self.conn.close()

        self.conn = None
        self.cursor = None

    def get_connection(self):
        return self.conn

    def get_cursor(self):
        return self.cursor

    def execute_sql(self, sql):
        disconnect_after_execute = False
        if self.cursor is None:
            self.connect()
            disconnect_after_execute = True

        try:
            self.cursor.execute(sql)
        except MySQLdb.OperationalError:
            self.disconnect()
            try:
                self.connect()
                self.cursor.execute(sql)
            except MySQLdb.OperationalError:
                '''
                Connection Loss
                '''
                self.disconnect()
                raise
        except MySQLdb.ProgrammingError:
            raise

        ret = self.cursor.fetchall()

        if disconnect_after_execute:
            self.conn.commit()
            self.disconnect()

        return ret

    @staticmethod
    def format_value(value):
        """
        This method format a value to a sql recognizable value, e.g. give a string abc will generate 'abc', give a
         bool True will give TRUE.
        :param value: value to format
        :return: sql value
        """
        v_formatted = 'NULL'
        # TODO: Date, Double type not considered
        if value is None:
            pass
        elif isinstance(value, basestring):
            v_formatted = "'%s'" % value
        elif isinstance(value, int) or isinstance(value, long):
            v_formatted = str(value)
        elif isinstance(value, bool):
            v_formatted = str(value).upper()
        else:
            v_formatted = "'%s'" % json.dumps(value)

        return v_formatted

    @classmethod
    def format_kv_pair(cls, dict_kv_pair):
        kv_pair = dict_kv_pair.items()
        sql_key = ', '.join(x[0] for x in kv_pair)
        sql_value = ', '.join(cls.format_value(x[1]) for x in kv_pair)
        return sql_key, sql_value

    @classmethod
    def format_where_and(cls, dict_kv_pair):
        return ' AND '.join(["%s=%s" % (k, cls.format_value(v)) for k, v in dict_kv_pair.items()])

    @classmethod
    def format_where_or(cls, dict_kv_pair):
        return ' OR '.join(["%s=%s" % (k, cls.format_value(v)) for k, v in dict_kv_pair.items()])

    @classmethod
    def format_where_single(cls, dict_kv_pair):
        return cls.format_where_and(dict_kv_pair)

    @classmethod
    def format_set(cls, dict_kv_pair):
        return ', '.join(' = '.join((k, cls.format_value(v))) for k, v in dict_kv_pair.items())

    @classmethod
    def sql_insert(cls, tbl, dict_kv_pair):
        keys, values = cls.format_kv_pair(dict_kv_pair)
        sql = "INSERT %s (%s) VALUES (%s)" % (tbl, keys, values)
        return sql

    @classmethod
    def sql_delete(cls, tbl, dict_filter, cond='AND'):
        if cond == 'AND':
            where_field = cls.format_where_and(dict_filter)
        else:
            where_field = cls.format_where_or(dict_filter)

        sql = "DELETE FROM %s WHERE %s" % (tbl, where_field)
        return sql

    @classmethod
    def sql_update(cls, tbl, dict_kv_pair, dict_filter, cond='AND'):
        if cond == 'AND':
            where_field = cls.format_where_and(dict_filter)
        else:
            where_field = cls.format_where_or(dict_filter)

        # TODO:IMPL THIS
        set_field = cls.format_set(dict_kv_pair)
        sql = "UPDATE %s SET %s WHERE %s" % (tbl, set_field, where_field)
        return sql

    @classmethod
    def sql_select(cls, tbl, select_field=None, dict_filter=None, cond='AND'):
        if select_field:
            select_field = ' '.join(x for x in select_field)
        else:
            select_field = '*'

        if dict_filter:
            if cond == 'AND':
                where_field = cls.format_where_and(dict_filter)
            else:
                where_field = cls.format_where_or(dict_filter)

            where_field = "WHERE %s" % where_field
        else:
            where_field = ""

        sql = "SELECT %s FROM %s %s" % (select_field, tbl, where_field)
        return sql
