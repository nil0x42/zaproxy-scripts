#!/usr/bin/python2

import re
import functools
import traceback
import pickle
import uuid
import pprint

from org.zaproxy.zap.extension.script import ScriptVars


# configuration
DEV_MODE = True
NAME = "exPscan"
MAX_BODY_SIZE = 300000

DATA_TYPES = {
        "js": ["javascript", "ecmascript"],
        "css": ["text/css"],
        "default": None,
        }

# don't touch these globales
_GLOB = {
        "REGEX": dict.fromkeys(DATA_TYPES, ""),
        "IREGEX": dict.fromkeys(DATA_TYPES, ""),
        "REG_BY_IDS": {},
        "ERRORS": "",
        }
_NONREG_STRINGS = """
## vi: ft=conf
## NOTE:
##  this file is a aggregate of strings that `should probably` be recognized.
##  It is useful for non-regression tests
##  * Lines starting with '#' are ignored
##
## vim tips:
##  remove duplicates:
##      :'<,'>!sort -u
##  sort by line length:
##      :'<,'>!awk '{ print length, $0 }' | sort -n -s | cut -d" " -f2-
DB2 ODBC
Index of
JDBC SQL
ODBC DB2
ODBC SQL
#DB2 Error #(always contains SQLSTATE, or SQL0204N like strings)
PHP Error
 server at 
#CLI Driver # (always contains SQL0420N like str)
#DB2 Driver
JDBC Error
JDBC MySQL
MySQL ODBC
ODBC Error
#Oracle DB2 # useless
Fatal error
JDBC Driver
JDBC Oracle
mysql error
MySQL Error
ODBC Driver
ODBC Oracle
Oracle ODBC
PHP Warning
data source=
Error Report
include_path
Invalid SQL:
MySQL Driver
Oracle Error
SQLException
invalid query
Oracle Driver
Type mismatch
Unknown table
database error
internal error
ODBC SQL Server
PHP Parse error
Parent Directory
unexpected error
ADODB.Field error
#ASP.NET_SessionId # irrelevant
mix of collations
SQL Server Driver
missing expression
server object error
#Warning: pg_connect # already detected to "on line [0-9]" regex in real life
Can't find record in
#Custom Error Message #???
#Warning: mysql_query # already detected ty "on line [0-9]" regex in real life
Incorrect column name
Incorrect syntax near
Internal Server Error
ODBC Microsoft Access
on MySQL result index
The error occurred in
Unable to jump to row
Can't connect to local
Disallowed Parent Path
Invalid parameter type
Invalid Path Character
mySQL error with query
ODBC SQL Server Driver
#Warning: mysql_query()
The script whose uid is
is not allowed to access
#Microsoft VBScript error # already caught in real life by microsoft regex '800a0400'
Microsoft VBScript error '800a0400'
Active Server Pages error
detected an internal error
A syntax error has occurred
Error Diagnostic Information
ODBC Microsoft Access Driver
Unterminated string constant
): encountered SQLException [
SQL Server Driver][SQL Server
unexpected end of SQL command
Permission denied: 'GetObject'
SQL command not properly ended
[ODBC Informix driver][Informix]
OLE/DB provider returned message
Syntax error in query expression
Invalid procedure call or argument
Invision Power Board Database Error
#Microsoft VBScript compilation error # already caught in real life by microsoft regex '800a0400'
You have an error in your SQL syntax
ERROR: parser: parse error at or near
Incorrect column specifier for column
Error Occurred While Processing Request
Microsoft OLE DB Provider for SQL Server
Unexpected end of command in statement [
You have an error in your SQL syntax near
internal error [IBM][CLI Driver][DB2/6000]
Microsoft OLE DB Provider for ODBC Drivers
[Microsoft][ODBC Microsoft Access 97 Driver]
Column count doesn't match value count at row
Error converting data type varchar to numeric
supplied argument is not a valid MySQL result
An unexpected token "END-OF-STATEMENT" was found
Error Message : Error loading required libraries.
java.lang.NumberFormatException: For input string:
Supplied argument is not a valid PostgreSQL result
PostgreSQL query failed: ERROR: parser: parse error
Unclosed quotation mark before the character string
An illegal character has been found in the statement
ASP.NET is configured to show verbose error messages
detected an internal error [IBM][CLI Driver][DB2/6000]
supplied argument is not a valid MySQL result resource
[SQL Server Driver][SQL Server]Line 1: Incorrect syntax near
Warning: Cannot modify header information - headers already sent
Warning: Supplied argument is not a valid File-Handle resource in
Warning: pg_connect(): Unable to connect to PostgreSQL server: FATAL
Incorrect syntax near
query failed
#not an object # too much false positives
error occurred
ERROR OCCURRED
Server Error
invalid file name
fatal error
parse error
ERROR 1049 (42000): Unknown database
No database selected
#exception report # not relevant on google hack search
Servlet error : java.lang.IndexOutOfBoundsException
"""


def exception_handler(function):
    """
    A decorator that wraps the passed in function and outputs
    exception instead if raising it, if DEV_MODE is True

    This is useful to not have to re-enable the script from ZAP
    each time we trigger an exception during development.
    """
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        if DEV_MODE:
            try:
                return function(*args, **kwargs)
            except:
                print("==== EXCEPTION CATCHED (DEV_MODE) ====")
                print(traceback.format_exc())
        else:
            return function(*args, **kwargs)
    return wrapper


def hash_source_code():
    """
    Get a hash representing the source code of current script
    It remains the same as long as source code has not changed
    """
    import ctypes
    from org.parosproxy.paros.control import Control

    script_name = globals()["zap.script.name"]

    extLoader = Control.getSingleton().getExtensionLoader()
    extScript = extLoader.getExtension("ExtensionScript")
    script_source = extScript.getScript(script_name).getContents()

    h = ctypes.c_uint32(hash(script_source)).value % 0xffffff
    return hex(h)[2:].zfill(6)


def str_to_lines(string):
    """yield non-empty lines from a multi-line string
    """
    for line in string.splitlines():
        if not line.strip():
            continue
        # ignore indentation spaces
        while line[:4] == "    ":
            line = line[4:]
        yield line


def sanitize_regex(regex):
    # this will not work anyway with current implementation
    assert not regex.startswith("^")
    assert not regex.endswith("$")

    # make internal groups non-capturing to limit overhead
    assert not "\\\\(" in regex
    regex = regex.replace("\\(", "_-*placeholder1*-_")
    regex = regex.replace("(?:", "_-*placeholder2*-_")
    regex = regex.replace("(", "(?:")
    regex = regex.replace("_-*placeholder1*-_", "\\(")
    regex = regex.replace("_-*placeholder2*-_", "(?:")

    # limit wildcards (.* & .+ can considerably slow down processing time)
    regex = regex.replace(".+", ".{1,40}")
    regex = regex.replace(".*", ".{,40}")

    return regex


def test_fail(obj, regex, line):
    global _GLOB
    word = "IGNORED" if obj else "FOUND"
    out  = "-"*50 + "\n"
    out += "[-] Test Failed: line should be %s by regex\n" % word

    if regex:
        out += "    REGEX: %s\n" % regex
    if line:
        out += "    LINE:  %s\n" % line
    if obj:
        out += "    MATCH: %r\n\n" % obj
    _GLOB["ERRORS"] += out


def process_regex(raw_regex, issue,
        test_finds="", test_ignores="", flags=0):
    global _GLOB

    issue_id = issue.replace(" ", "_kw_") + str(uuid.uuid4())[:8]

    assert issue_id not in _GLOB["REG_BY_IDS"]
    _GLOB["REG_BY_IDS"][issue_id] = raw_regex

    regex = "(?P<%s>%s)" % (issue_id, sanitize_regex(raw_regex))

    # execute unit tests
    test = re.compile(regex, flags)
    for line in str_to_lines(test_finds):
        res = test.findall("\n"+line+"\n")
        if not res:
            test_fail(res, regex, line)
    for line in str_to_lines(test_ignores):
        res = test.findall("\n"+line+"\n")
        if res:
            test_fail(res, regex, line)

    return regex


def add_strings(issue_name, strings):
    global _GLOB
    for line in str_to_lines(strings):
        regex = process_regex(r"\b%s\b" % line, issue_name)
        for t in DATA_TYPES:
            if _GLOB["REGEX"][t]:
                _GLOB["REGEX"][t] += "|"
            _GLOB["REGEX"][t] += regex


def add_regex(issue_name, regex,
        test_finds, test_ignores="", ignored_types=""):
    global _GLOB
    regex = process_regex(regex, issue_name,
            test_finds, test_ignores)

    ignored_types = ignored_types.split()
    for t in DATA_TYPES:
        if t in ignored_types:
            continue
        if _GLOB["REGEX"][t]:
            _GLOB["REGEX"][t] += "|"
        _GLOB["REGEX"][t] += regex


def add_iregex(issue_name, regex,
        test_finds, test_ignores="", ignored_types=""):
    global _GLOB
    regex = process_regex(regex, issue_name,
            test_finds, test_ignores, re.I)

    ignored_types = ignored_types.split()
    for t in DATA_TYPES:
        if t in ignored_types:
            continue
        if _GLOB["IREGEX"][t]:
            _GLOB["IREGEX"][t] += "|"
        _GLOB["IREGEX"][t] += regex


def build_matcher():

    ############################################################
    name = "PHP Source code disclosure"

    add_regex(name, r"<\?(php\s|\=)",
        test_finds = """
        data="<?php
        <?=$data;?>
        """,
        test_ignores = """
        <?PhP
        <?PhPa
        <?PhP0
        <?
        < ? php
        < ? =
        """)

    add_strings(name, " => Array")

    add_regex(name, r"\$[a-zA-Z_][a-zA-Z0-9_]+\[",
        test_finds = """
        &nbsp;mysqli_connect($config['host'],&nbsp;
        $_POST[0]
        $_GET["x"]
        $ee[
        """,
        test_ignores = """
        $#[
        $1[
        $$_GET  ["x"]
        $_GET  ["x"]
        a$a[
        $e[
        """,
        ignored_types = "js")


    ############################################################
    name = "JAVA Source code disclosure"

    add_regex(name, r'\bimport javax?\.[a-zA-Z0-9.]+;',
        test_finds = """
        import java.io.File;
        import java.net.MalformedURLException;
        import javax.servlet.http.HttpServlet;
        """,
        test_ignores = """
        Ximport javax.servlet.http.HttpServlet;
        """)

    add_regex(name, r'\bclass( \w+){1,3}\s*\{',
        test_finds = """
        public class SimpleServlet extends HttpServlet {
        public class TestGate {
        public class TestGate{
        """,
        test_ignores = """
        public class {
        """)


    ############################################################
    name = "ASP Source code disclosure"

    add_strings(name, "On Error Resume Next")


    ############################################################
    name = "ASP NET Source code disclosure"

    add_regex(name, r'@Render[A-Z][a-z]+',
        test_finds = """
        @RenderPage
        @RenderBody
        @RenderSection
        """)


    ############################################################
    name = "C Source code disclosure"

    add_regex(name, r'#(include|define|ifn?def|endif)\b',
        test_finds = """
        #include x
        #define
        #ifdef
        #ifndef
        #endif
        """,
        test_ignores = """
        #includes
        """)


    ############################################################
    name = "Cold Fusion Source code disclosure"

    add_regex(name, r'<cf(argument|component|dump|else|elseif|execute|exit|function|if|loop|output|query|queryparam|return|script|set)\b',
        test_finds = """
        <cfargument
        <cfcomponent
        <cfdump
        <cfelse
        <cfelseif
        <cfexecute
        <cfexit
        <cffunction
        <cfif
        <cfloop
        <cfloop
        <cfoutput
        <cfquery
        <cfqueryparam
        <cfreturn
        <cfscript
        <cfset
        """,
        test_ignores = """
        <cfX
        <cfx
        <cf
        <CFIF
        <CfDump
        """)


    ############################################################
    name = "Source code disclosure"

    add_regex(name, r'[A-Za-z._]+(Exception|Error|Controller|Servlet|Object|Client|Connection|Driver)([^a-z]|$)',
        test_finds = """
        System.Exception
        SQLException
        SQLite/JDBCDriver
        AppDomain.CurrentDomain.UnhandledException
        java.lang.RuntimeException
        Type: RuntimeException
        aspController()
        MysqlController.CheckMysqlIsRunning()
        ErrorController.php5</b> on line <b>73</b><br />
        AuthPluginController.php on line <i>58</i>
        RuntimeError: Expected object of type
        (RuntimeError) Element does not exist in cache
        @WebServlet
        HTTPServlet
        Server.CreateObject 
        of type 'System.__ComObject
        The type or namespace name `Data.MySqlClient' could not be found.
         Class 'mysqlConnection' not found.
        Zend_Db_Statement_Db2_Exception
        Zend_Db_Adapter_Db2_Exception
        ArrayObject Object
        Servlet error : java.lang.IndexOutOfBoundsException
        """,
        test_ignores = """
        Exception
        XExceptions
        Errors
        Bad Error.
        Controllers
        #Controller
        """,
        ignored_types = "js css")

    add_regex(name, r' runat=',
        test_finds = """
        <umbraco:Macro runat="server" language="cshtml">
        <script runat="server">
        <asp:Foo runat="server">
        <head id="Head1" runat="server">
        """)

    add_regex(name, r"<%(@|=)?\s*[A-Za-z]{2,}",
        test_finds = """
        <%@ taglib prefix="jcr"
        <%@ include file="webftpclass.jsp"
        <%@ page errorPage
        <%@ Page Language="C#" %>
        <% int x = 5; %>
        <%@ Page Inherits="ParentPageClass" %>
        <% Sub SomeProcedure() %>
        <% End Sub %>
        <%Assembly
        <%OutputCache
        <%Implements
        """)

    add_regex(name, r'\b(static\s+void|void\s+static)\b',
        test_finds = """
        public void static main(
        public static void main(
        public  static  void  main(
        """)

    add_regex(name, r"<[aj]sp:[a-zA-Z]",
        test_finds = """
        <jsp:directive.taglib uri = "uri" prefix = "prefixOfTag" />
        <asp:TreeView id="SiteTreeView" DataSourceID=
        <asp:SiteMapDataSource id="MenuSource"
        """)

    add_iregex(name, r'\s@(for\s?each|switch|select|interface|implementation|protocol|private|synthesize|property)\s',
        test_finds = """
        @interface Foo : NSObject {
        @PRIVATE
        @foreach
        @For Each
        @property
        @synthesize
        """,
        test_ignores = """
        @For EachX
        @foreachX
        @ends
        admin@private.com
        admin@privates.com
        """)

    add_iregex(name, r'\b(connection|query)string\b',
        test_finds = """
        ConnectionString = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" & m_strDatabase & ";Persist Security Info=False"
        Convert.ToInt32(Request.QueryString["pID"]);
        oledb.oledbConnection(connectionString)'
        oRequest.querystring 
        """,
        test_ignores = """
        Parse and stringify URL query strings
        A query string is the portion of ...
        connection string
        """,
        ignored_types = "js")

    add_iregex(name, r'\bdata\s*source\s*=',
        test_finds = """
        ConnectionString = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=" & m_strDatabase & ";Persist Security Info=False"
        Data Source={DataDirectory}\test.db;
        "Data Source=(local);Database=Northwind;User ID=springqa;Password=springqa;
        """)


    ############################################################
    name = "ASP Error message"

    add_regex(name, r"\bASP [01]\d{3}\b",
        test_finds = """
        ctive Server Pages error 'ASP 0131', Disallowed Parent
        Error Message: ASP 0131, Disallowed Parent 
        Active Server Pages error 'ASP 0131'
        Active Server Pages error 'ASP 0113' 
        'ASP 0115' Unexpected Error
        """,
        test_ignores = """
        ASP 2008
        ASP 2000
        """)

    add_strings(name, """
        Active Server Pages error
        Disallowed Parent Path
        """)


    ############################################################
    name = "PHP Error message"

    add_regex(name, r"<b>(Notice|Deprecated)</b>: ",
        test_finds = """
        <b>Notice</b>:  Undefined offset: 6
        <b>Deprecated</b>:  Non-static method
        """,
        test_ignores = """
        """)

    add_iregex(name, r"\b(warning|error)\b.*?: +(<.+?>)?[a-zA-Z_][a-zA-Z0-9_]+\(",
        test_finds = """
        <b>Warning</b>:  require_once(../body.asp)
        ;;Warning: require_once(../body.asp)
        /Warning: require_once(../body.asp)
        Warning: require_once(../body.asp)
        <b>Fatal error</b>:  require_once() 
        <b>Warning</b> (2)</a>: mysqli_connect() 
        &nbsp;Error: </td><td colspan='2'>mysql_connect(): Lost connection to MySQL server
        <b>Warning</b>:  mysqli_fetch_assoc()
        """,
        test_ignores = """
        error: x()
        fatal error:  require_once ()
        """,
        ignored_types = "js")

    add_regex(name, r'</b> on line <b>[0-9]+</b>',
        test_finds = """
        in <b>D:\wwwroot\test.asp</b> on line <b>2</b>
        ErrorController.php5</b> on line <b>73</b><br />
        errorhandler.php</b> on line <b>218</b><br>
        wp-config.php.old</b> on line <b>61</b><br />
        /dvds.cfm</b> on line <b>166</b><br>
        main_index.cgi</b> on line <b>75</b><br>
        WebCalendar.class</b> on line <b>18</b>
        """,
        test_ignores = """
        """)

    # [10-May-2014 04:58:13 UTC] PHP Warning: Module 'newrelic' already loaded in Unknown on line 0
    # Warning: Cannot modify header information - headers already sent
    # Warning: Supplied argument is not a valid File-Handle resource in
    add_strings(name, """
        PHP Warning
        Cannot modify header information
        Supplied argument is not a valid
        include_path
        The script whose uid is
        """)


    ############################################################
    name = "Error message"

    add_regex(name, r"\.(aspx?|php[0-9]?|inc|cfm|old|cgi|jsp|html?|class)\b.*?\b[Ll]ine\b.*?[0-9]+",
        test_finds = """
        /download.asp</font><font face="Arial" size=2>, line 12</font>
        /download.asp, line 12
        route.php, line 12
        route.inc, line 12
        APP/webroot/index.php, line 87</pre>
        C:\html\pdf.aspx<b> &nbsp;&nbsp; Line: </b> 334
        \SQLServer_connection.aspx Line: 33 
        events.aspx:line 14 -->
        AuthPluginController.php on line <i>58</i>
        should not be called statically in file /home/storage/handler.php line 230<br>
        Error in C:\inetpub\Default.aspx on line 322
        /new.php on line 2
        """,
        test_ignores = """
        asp, line
        aspon line
        xasp, line
        Xphp, lineXX3X
        XPHPXLINE
        """,
        ignored_types="css")

    add_regex(name, r"\.(aspx?|php[0-9]?|inc|cfm|old|cgi|jsp|html?|class)\b\s*(<.*?>)?\s*:\s*(<.*?>)?\s*[0-9]+",
        test_finds = """
        in e:\WWW\pdf.aspx:380
        (output started at /wwwroot/err.php:272)
        in /home/storage/2/21/af/sbmp/public_html/cbab/siscbab/include/common.php:63
        >../Bootstrap.php<b>:</b>97</td></tr>
        undefined function mysql_connect() in /home1/dbi.php:105
        """,
        test_ignores = """
        """)

    add_iregex(name, r"\bbacktrace\b",
        test_finds = """
        X backTrace X
        class.backTrace
        """,
        test_ignores = """
        backtraces
        xbackTrace
        """)

    add_iregex(name, r"\bstack.trace\b",
        test_finds = """
        <b>Stack Trace:</b> <br><br>
        Please review the stack trace for more information
        stack-trace
        """,
        test_ignores = """
        """,
        ignored_types = "js")

    add_iregex(name, r"\bunable to cast ",
        test_finds = """
        Unable to cast object of type 
        Unable to cast object of type 'proje.hesap' to type
        Unable to cast COM object of type 'System.__ComObject'
        """,
        test_ignores = """
        """)

    add_iregex(name, r"\b(internal|fatal|unhandled|unexpected|uncaught) ?(exception|error)\b",
        test_finds = """
        An unexpected error occurred on a send.
        unhandled error
        internal error
        Connection Lost: Internal Exception: java.io.IOException: An established connection was aborted
        """,
        test_ignores = """
        Xinternal error
        """,
        ignored_types = "js")

    add_iregex(name, r"\b(syntax|parse|runtime) error\b",
        test_finds = """
        syntax error near unexpected token `('
        Error: syntax error near \":=\" : expected '.'
        org.postgresql.util.PSQLException: ERROR: syntax error at or near "$1"
        Error :: ERROR: syntax error at or near "TYPE" at character 51
        ERROR: parser: parse error at or near
        Microsoft VBScript runtime error '800a000d' Type mismatch
        """,
        test_ignores = """
        runtime X error
        runtime errors
        """,
        ignored_types = "js")

    add_iregex(name, r"\b(error|exception)\b.*?\bwhile (attempting|trying) to ",
        test_finds = """
        ERROR: I/O or zip error while attempting to read entry
        Error while attempting to commit transaction.
        There was an unexpected error while trying to repair Trusted
        Error while trying to run project : Unable to start debugging.
        NamingException: Exception while trying to get InitialContext. 
        threw an exception while trying to deserialize the 
        WARNING: Exception while attempting to add an entry
        [CASSANDRA-12152] Unknown exception caught while attempting to update
        Exception thrown while attempting to traverse the result set [
        An unexpected exception occurred while attempting to communicate
        MODx encountered the following error while attempting to '
        """,
        ignored_types = "js")

    add_iregex(name, r"\b(error|exception) (\w+ )?(encountered|occurr?ed)\b",
        test_finds = """
        A PHP Error was encountered
        <h4>A PHP Error was encountered</h4>
        Warning. Error encountered while saving cache
        Exception encountered during initialization
        An unexpected exception occurred while attempting to communicate
        A COM exception has occured.
        """,
        test_ignores = """
        Xerrror was encountered
        """,
        ignored_types = "js")

    add_iregex(name, r"\error (occurr?ed|loading|encountered|report|message|converting|diagnostic)",
        test_finds = """
        error messages
        error loadinG
        Error Diagnostic Information
        Error Report
        """,
        ignored_types = "js")

    add_regex(name, r'\b[Ee]ncountered an? (\w+ )?(error|exception)\b',
        test_finds = """
        BackupManager encountered an exception
        Sorry, we encountered an error....
        TypeError: ServiceWorker script encountered an error during
        NTVDM encountered a hard error
        [Server thread/ERROR]: Encountered an unexpected exception net.
        encountered a declaration exception
        Debugger encountered an exception: Exception at 0x7ffd21349e08
        DJLDAPv3Repo encountered an ldap exception.
        The server encountered a temporary error and could not complete your request
        """,
        test_ignores = """
        But I encountered with a strange error, it says,
        If the error encountered is a softer error, such as an ...
        """)

    add_iregex(name, r'\bconnection (was |is )?closed\b',
        test_finds = """
        The underlying connection was closed
        An unrecoverable IOException occurred so the connection was closed.
        System.Net.WebException: The underlying connection was closed
        Database connection closed on port
        Connection closed by foreign host.
        Exception:Message: The connection is closed
        """,
        test_ignores = """
        Xconnection was closed
        connection was closedX
        """)

    add_iregex(name, r'\b(php|server) (\w+ )?error\b',
        test_finds = """
        &laquo; PHP Parse Error &raquo;</b>
        <b>PHP error debug</b>
        <H1>Server Error in '/EMCFLEXQUOTE' Application.<hr
        """,
        test_ignores = """
        some php errors
        observer error
        servererror
        server errors
        """,
        ignored_types = "js")

    add_iregex(name, r'(login|access|authentication|permission) (failed|failure|denied)',
        test_finds = """
        Authentication failed for user root@localhost.localdomain.
        FATAL: Ident authentication failed for user "pgadmin" 
        Access denied for user 
        Microsoft VBScript runtime (0x800A0046). Permission denied.
        SQLSTATE[HY000] [1045] Access denied for user 'root'@'localhost'
        """,
        ignored_types = "js")

    add_iregex(name, r'\b(unterminated|unexpected) (end|token|string)\b',
        test_finds = """
        Parse error: syntax error, unexpected end of file in
        compile error: unexpected end of script
        unexpected end-of-file occurred
        ORA-00921: unexpected end of SQL command
        syntax error near unexpected token `('
        An unexpected token "END-OF-STATEMENT" was found
        Unterminated string constant 
        SyntaxError: unterminated string literal
        error: unterminated string
        """,
        ignored_types = "js")

    add_strings(name, """
        is not allowed to access
        """)


    ############################################################
    name = "Microsoft Error message"

    add_iregex(name, r'[x\W\b]800(40|a0|04)[a-f0-9]{3}\b',
        test_finds = """
        Microsoft VBScript runtime error '800a000d' Type mismatch
        6 Microsoft JET Database Engine Error '80004005' 
        Microsoft SQL Native Client error '80004005' Named Pipes
        Microsoft VBScript runtime (0x800A0046). Permission denied.
        Microsoft SQL Native Client error '80004005'. Cannot open database
        Microsoft SQL Native Client error '80004005'. Login failed for user 'Admin'
        Microsoft SQL Native Client error '80040e37'.
        """,
        test_ignores = """
        """)


    ############################################################
    name = "DB2 SQL Error message"

    add_regex(name, r"\bSQL\d{4}N\b",
        test_finds = """
        [IBM][CLI Driver][DB2] SQL0443N Routine "SQLTABLES" (specific name "SQLTABLES") has returned an error SQLSTATE with
        During SQL processing it returned: SQL0204N
        nput Data (33) Error SQLExtendedFetch: [IBM][CLI Driver][DB2/AIX64] SQL0420N Invalid character found in a character string argument of the function "DECFLOAT". SQLSTATE=22018
        """)

    ############################################################
    name = "Oracle SQL Error message"

    add_regex(name, r"(\b|^)ORA-\d{5}(\b|$)",
        test_finds = """
        ORA-00921: unexpected end of SQL command
        ORA-29282: invalid file ID
        ORA-00933: SQL command not properly terminated. 
        ou,ORA-28002:,the,password,
        """)


    ############################################################
    name = "SQL Error message"

    #check the manual that corresponds to your MySQL server version for
    #check the manual that corresponds to your MariaDB server version for
    #error in your SQL syntax
    add_strings(name, """
        error in your SQL syntax
        check the manual that corresponds to your
        Can't find record in
        Type mismatch
        mix of collations
        Unable to jump to row
        missing expression
        Can't connect to local
        Invalid Path Character
        Column count doesn't match value count at row
        Unclosed quotation mark before the character string
        An illegal character has been found in the statement
        No database selected
        """)

    add_iregex(name, r"\b(unknown|invalid|incorrect) (column|table|query|sql|parameter|procedure|syntax|database|file)",
        test_finds = """
        Error 1054 Unknown column 'a.category' in 'where clause'
        Debug info: Unknown column 'groupmembersonly' in 'where clause' SELECT
        Unknown column 'a.id' in 'on clause' 
        PHP Fatal error: 1054 :Unknown column 'status' in 'where clause'
        Data.SqlClient.SqlException: Invalid column name 'apikeytime'.
        [Microsoft][SQL Server Native Client 10.0][SQL Server]Invalid column name 'U_FOC'.
        Warning: Requested unknown parameter
        stored procedure: Invalid Parameter Type.
        Invalid procedure call or argument
        Incorrect syntax near
        ORA-29282: invalid file ID
        """,
        ignored_types = "js")

    add_iregex(name, r"sql[ _]?(state|code)\b",
        test_finds = """
        Connection failed : SQL state S1 T00 SQL SERVER ERROR 0
        SQL State 3000
        SQL STATE: S1000 ERROR CODE: -25. ERROR IN SCRIPT LINE FILE: 78'
        Database error: SQL State 'HYC00';
        [SQLDriverConnect]{SQL_STATE: IM002}[Microsoft][ODBC Driver Manager]'
        Warning C4251 'sql::SQLException::sql_state': class 'std::
        SQLSTATE[HY000] [14] unable to open database file
        SQLSTATE[HY000] [1045] Access denied for user 'root'@'localhost'
        SQLSTATE[42000]: Syntax error or access violation: 1064
        mysql state: 28000
        [IBM][CLI Driver][DB2] SQL0443N Routine "SQLTABLES" (specific name "SQLTABLES") has returned an error SQLSTATE with
        Exception: [Informix][Informix ODBC Driver]Driver not capable. SQLCODE=-11092
        nput Data (33) Error SQLExtendedFetch: [IBM][CLI Driver][DB2/AIX64] SQL0420N Invalid character found in a character string argument of the function "DECFLOAT". SQLSTATE=22018
        """,
        test_ignores = """
        sqlstates
        sql states
        sql codes
        """)

    add_regex(name, r"\b not properly (ended|terminated)\b",
        test_finds = """
        quoted string not properly terminated
        SQL command not properly ended
        ORA-00933: SQL command not properly terminated. 
        """,
        test_ignores = """
        """)

    add_iregex(name, r"\b[jo]dbc\b",
        test_finds = """
        com.mysql.jdbc
        org.postgresql.jdbc
        SQLServer JDBC Driver
        macromedia.jdbc.sqlserver
        com.microsoft.sqlserver.jdbc
        macromedia.jdbc.oracle
        oracle.jdbc
        com.informix.jdbc
        weblogic.jdbc.informix
        org.firebirdsql.jdbc
        org.sqlite.JDBC
        com.sap.dbtech.jdbc
        com.sybase.jdbc
        com.ingres.gcf.jdbc
        com.frontbase.jdbc
        org.hsqldb.jdbc
        org.h2.jdbc
        com.microsoft.sqlserver.jdbc.SQLServerException: Violation of PRIMARY KEY constraint
        .jdbc'
        Exception: [Informix][Informix ODBC Driver]Driver not capable. SQLCODE=-11092
        [Microsoft][ODBC SQL Server Driver][SQL Server]
        PostgreSQL ODBC error
        [SQLDriverConnect]{SQL_STATE: IM002}[Microsoft][ODBC Driver Manager]'
        Warning: SQL error: [INTERSOLV][ODBC SQL Server driver][SQL Server]Invalid column name 'projanfang'
        [S1090] [Microsoft][ODBC DB2 Driver] Invalid string or buffer length.
        """,
        test_ignores = """
        xjdbc
        jdbcx
        """)

    add_iregex(name, r'(sql|\bdb2|\b[oj]dbc|\bsqlite|\bdatabase|\boracle|\bdb|\bquery)\s+(\w+\s+)?(driver|failed|error|exception|warning|engine)\b',
        test_finds = """
        Access Database Engine
        <b>Database error:</b> Invalid SQL:
        <b>MySQL Error</b>: 
        Database error occured: #1950 (2627) Generic db error: "2627 
        Database error: SQL State 'HYC00';
        Dynamic SQL Error SQL Error code = -204 Table UNKNOW
        Exception: [Informix][Informix ODBC Driver]Driver not capable. SQLCODE=-11092
        JET Database Engine
        >&laquo; Execution of a query to the database failed &raquo;
        [Microsoft][ODBC SQL Server Driver][SQL Server]
        Postgresql CDC Error
        PostgreSQL ODBC error
        PostgreSQL query failed
        [SQLDriverConnect]{SQL_STATE: IM002}[Microsoft][ODBC Driver Manager]
        SQLite error 11: database disk 
        The Microsoft Jet database engine cannot open the file
        Warning: SQL error: [INTERSOLV][ODBC SQL Server driver][SQL Server]Invalid column name 'projanfang'
        """,
        test_ignores = """
        some sql errors
        """)

    add_regex(name, r'(oledb|OLE[\W_]?DB)\b',
        test_finds = """
        oraOLEDB.Oracle: Provider not found: Oracle 1
        provider=MYSQLOLEDB; Driver={MySQL};SERVER=localhost
        Codigo de Excepcion OLE IDispatch 0 de Microsoft OLE DB Provider SQL Server
        oledb.oledbConnection(connectionString)'
        OraOLEDB
        Provider=Microsoft.Jet.OLEDB.4.0;
        OLE_DB
        """,
        test_ignores = """
        OLE_DBX
        XOLE_DBX
        OL_DBX
        """)

    # removed 'ingres' because of false positives
    add_iregex(name, r'(^|[\W\s_])(adodb|informix|sybase|sqlite|mssql|mysql|oracle|hsqldb)([\W\s_]|$)',
        test_finds = """
        X_INFORMIX_X
        com.informix.jdbc
        weblogic.jdbc.informix
        Exception: [Informix][Informix ODBC Driver]Driver not capable. SQLCODE=-11092
        [ADODB.Connection]
        """,
        test_ignores = """
        sybaseX
        Xsybase
        """)


    ############################################################
    name = "SQL Query disclosure"

    add_iregex(name, r'\b(create|drop)\s+(database|table|view|index|procedure|function)\b',
        test_finds = """
        create Database
        create table
        CREATE view
        creAte  index
        create  procedure
         create\tfunction
        drop Database
        drop table
        DROP view
        drop index
        drop  procedure
        drop function
        """,
        test_ignores = """
         create\tfunctions
        Xdrop Database
        """)


    ############################################################
    name = "Leaked file path"

    add_strings(name, "file://")

    add_regex(name, r'(/|\\)Users(/|\\)',
        test_finds = """
        marketplace_file:///C:/Users/sh
        """,
        test_ignores = """
        inetpubX
        """)

    add_regex(name, r'\b[CDE]:(/|\\)',
        test_finds = r"""
        /C:/bla
        E:\bla
        """,
        test_ignores = """
        C:
        XC:/bla
        """)

    add_regex(name, r"/(home|var|www|usr)/",
        test_finds = """
        /home/www/
        daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
        """,
        test_ignores = """
        homepage
        /HOME/
        # www.google.com/support/webmasters/bin/answer.py?hl=en&answer=156449
        """)

    add_regex(name, r"\b(public_html|wwwroot|inetpub|xampp|htdocs)\b",
        test_finds = """
        /var/www/public_html/index.php
        on wwwroot
        in c:/inetpub/wwwroot
        in D:\Inetpub\wwwroot
        """,
        test_ignores = """
        wwwroots
        Public_Html
        """)


    ############################################################
    name = "Unix Shebang disclosure"

    add_regex(name, r"[\s^]#!/(bin|usr)/",
        test_finds = """
        #!/usr/bin/perl
        #!/bin/bash
        """,
        test_ignores = """
        $#!/usr/bin/perl
        "#!/usr/bin/perl"
        """)


    ############################################################
    name = "Directory Listing"

    add_regex(name, r'\b(Index of|Parent Directory|Directory [Ll]isting)\b',
        test_finds = """
        <title>Directory Listing For /</title>
        <H1>Directory listing for /</H1>
        <title>Directory Listing</title>
        <h1>Index of /phy
        >Parent Directory</a>
        Parent Directory
        <h1>Index of /p
        """,
        ignored_types= "js")

    add_regex(name, r' alt="\[(DIR|PARENTDIR|IMG)\]"',
        test_finds = """
        <td style="padding-right:15px"><img src="/layout/i/folder.gif" alt="[DIR]"></td>
        <img src="/__ovh_icons/back.gif" alt="[PARENTDIR]"> <a href="/content/">Parent Directory</a> 
        <img src="/__ovh_icons/image2.gif" alt="[IMG]"> 
        """)


    ############################################################
    name = "Product disclosure"

    add_iregex(name, r"\bpowered by\b",
        test_finds = """
        Powered by: vBulletin v3.8.4
        """,
        test_ignores = """
        """)

    add_iregex(name, r" server at ",
        test_finds = """
        Proudly Served by LiteSpeed Web Server at xxx.com
        """)


    ############################################################
    name = "Google Analytics UA Tracking ID"

    # https://stackoverflow.com/questions/2497294/regular-expression-to-validate-a-google-analytics-ua-number
    # https://www.drupal.org/project/google_analytics/issues/1336252
    add_regex(name, r"\WUA-\d{4,10}(-\d{1,4})?[^\w-]",
        test_finds = """
        "UA-12345678"
        "UA-12345678-12"
        """,
        test_ignores = """
        XUA-12345678"
        "UA-12345678-12X"
        "UA-12345678X"
        """)


    ############################################################
    name = "E Mail disclosure"

    add_regex(name, r"(?:\bmailto:)[^'\" ]+",
        test_finds = """
        maintained by <A HREF="mailto:lonsa@ncu.edu">
        """)

    add_regex(name, r"\b[\w.+-]+@[a-zA-Z0-9]+[a-zA-Z0-9-]*\.[a-zA-Z0-9-.]*[a-zA-Z0-9]{2,}",
        test_finds = """
        "admin@test.com"
        """,
        test_ignores = """
        *@123
        $@#!.
        """)

    # build `matcher` (regex_list, regex_ids)
    regex_list = {"REGEX": {}, "IREGEX": {}}
    for dt in DATA_TYPES.keys():
        regex_list["REGEX"][dt] = _GLOB["REGEX"][dt]
        regex_list["IREGEX"][dt] = _GLOB["IREGEX"][dt]
    regex_ids = _GLOB["REG_BY_IDS"]
    matcher = (regex_list, regex_ids)

    # nonreg test: ensure all lines are matched as suspicious
    for line in str_to_lines(_NONREG_STRINGS):
        if line.startswith("#"):
            continue
        res = scan_body(line, "default", matcher)
        if not res:
            test_fail(res, None, line)
            
    # display errors if any test failed
    if _GLOB["ERRORS"]:
        print(_GLOB["ERRORS"])
        raise Exception("Some tests failed")
    if DEV_MODE:
        print("[+] build_matcher(): Matcher successfully built")
    return matcher


def scan_body(data, data_type, matcher):
    regex_list, regex_ids = matcher
    matches = {}
    for regex_type in regex_list.keys():
        regex = regex_list[regex_type][data_type]
        flags = re.I if regex_type == "IREGEX" else 0
        regex = re.compile(regex, flags)
        for m in regex.finditer(data):
            start_pos = m.start()
            issue_id = m.lastgroup
            matches[start_pos] = {
                    "str": m.group(issue_id),
                    "regex": regex_ids[issue_id],
                    "issue": issue_id[:-8].replace("_kw_", " "),
                    }
    return matches


def get_data_type(content_type):
    """get the data type (one of DATA_TYPES keys)
    """
    for key, val in DATA_TYPES.items():
        if key == "default":
            continue
        for match in val:
            if match in content_type:
                return key
    return "default"

@exception_handler
def scan(ps, msg, src):
    if DEV_MODE:
        print("\n--------------------")
        print("[*] %s script started" % NAME)
    # Docs on alert raising function:
    #  raiseAlert(int risk, int confidence, str name, str description, str uri,
    #             str param, str attack, str otherInfo, str solution,
    #             str evidence, int cweId, int wascId, HttpMessage msg)
    #  risk: 0: info, 1: low, 2: medium, 3: high
    #  confidence: 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed

    old_script_hash = max(ScriptVars.getGlobalVar(NAME+"_hash"), "")
    script_hash = hash_source_code()

    if script_hash == old_script_hash:
        matcher = pickle.loads(ScriptVars.getGlobalVar(NAME+"_matcher"))
    else:
        ScriptVars.setGlobalVar(NAME+"_hash", script_hash)
        matcher = build_matcher()
        ScriptVars.setGlobalVar(NAME+"_matcher", pickle.dumps(matcher))

    if DEV_MODE:
        print("[+] Got matcher, now scanning body")
    body = msg.getResponseBody()
    hdr = msg.getResponseHeader()
    uri = msg.getRequestHeader().getURI().toString()
    if DEV_MODE:
        print("[*] URI = %s" % uri)

    content_type = max(hdr.getHeader(hdr.CONTENT_TYPE), "")
    content_type = content_type.split(";", 1)[0].strip()
    blacklist = ["audio/", "video/"]
    if any(s in content_type for s in blacklist):
        if DEV_MODE:
            print("[-] Blacklisted content-type %r: aborting" % content_type)
        return

    data = body.toString()[:MAX_BODY_SIZE]
    data_type = get_data_type(content_type)
    if DEV_MODE:
        print("[*] data_type = %s" % data_type)
    matches = scan_body(data, data_type, matcher)

    found_evidences = []
    for start_pos in sorted(matches):
        match = matches[start_pos]
        title = "%s: %s (script)" % (NAME, match["issue"])
        desc = "Regular Expression:\n  %s" % match["regex"]
        evidence = match["str"]
        if evidence in found_evidences:
            continue
        found_evidences.append(evidence)
        if DEV_MODE:
            print("  -> GOT MATCH: %s" % title)
        ps.raiseAlert(0, 1, title, desc, uri, None,
                        None, None, None, evidence, 0, 0, msg)
    if DEV_MODE:
        print("[+] Body correctly scanned")


def appliesToHistoryType(histType):
    """
    Limit scanned history types, which otherwise default to
    types in `PluginPassiveScanner.getDefaultHistoryTypes()`
    """
    #from org.parosproxy.paros.model import HistoryReference as hr
    from org.zaproxy.zap.extension.pscan import PluginPassiveScanner

    #return histType in [hr.TYPE_PROXIED, hr.TYPE_SPIDER]
    return histType in PluginPassiveScanner.getDefaultHistoryTypes()


