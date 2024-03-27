# -*- coding:utf-8 -*-

import uuid

from flask import abort
from flask import current_app
from flask import session
from ldap3 import ALL
from ldap3 import AUTO_BIND_NO_TLS
from ldap3 import Connection
from ldap3 import Server
from ldap3.core.exceptions import LDAPBindError
from ldap3.core.exceptions import LDAPCertificateError
from ldap3.core.exceptions import LDAPSocketOpenError
from ldap3 import ALL_ATTRIBUTES
from api.lib.common_setting.common_data import AuthenticateDataCRUD
from api.lib.common_setting.const import AuthenticateType
from api.lib.perm.acl.audit import AuditCRUD
from api.lib.perm.acl.resp_format import ErrFormat
from api.models.acl import User

SERVER_USER = 'cn=admin,dc=hzguode,dc=com'
SERVER_PASSWORD = "XXXXX"
active_base_dn = 'dc=hzguode,dc=com'  # 正式员工账户所在OU
search_filter = '(objectclass=inetOrgPerson)'  # 只获取【用户】对象


def authenticate_with_ldap(username, password):
    config = AuthenticateDataCRUD(AuthenticateType.LDAP).get()

    server = Server(config.get('ldap_server'), get_info=ALL, connect_timeout=3)
    if '@' in username:
        email = username
        who = config.get('ldap_user_dn').format(username.split('@')[0])
    else:
        who = config.get('ldap_user_dn').format(username)
        email = "{}@{}".format(who, config.get('ldap_domain'))
    print(email)
    username = username.split('@')[0]
    user = User.query.get_by_username(username)
    try:
        if not password:
            raise LDAPCertificateError
        try:
            conn0 = Connection(server, user=SERVER_USER, password=SERVER_PASSWORD, auto_bind=AUTO_BIND_NO_TLS)
        except LDAPBindError:
            print("ldap的管理员账号密码连接出错")
        # my_dn,mymail = dn_get(conn0, user)
        my_dn = dn_get(conn0, user)
        mymail = mail_get(conn0, user)
        who = my_dn
        email=mymail
        print("email"+email)
        try:
            conn = Connection(server, user=who, password=password, auto_bind=AUTO_BIND_NO_TLS)
        except LDAPBindError:
            conn = Connection(server,
                              user=f"{username}@{config.get('ldap_domain')}",
                              password=password,
                              auto_bind=AUTO_BIND_NO_TLS)

        if conn.result['result'] != 0:
            AuditCRUD.add_login_log(username, False, ErrFormat.invalid_password)
            raise LDAPBindError
        else:
            _id = AuditCRUD.add_login_log(username, True, ErrFormat.login_succeed)
            session['LOGIN_ID'] = _id

        if not user:
            from api.lib.perm.acl.user import UserCRUD
            user = UserCRUD.add(username=username, email=email, password=uuid.uuid4().hex)

        return user, True

    except LDAPBindError as e:
        current_app.logger.info(e)
        return user, False

    except LDAPSocketOpenError as e:
        current_app.logger.info(e)
        return abort(403, ErrFormat.ldap_connection_failed)


def users_get(conn):
    '''获取所有的用户'''
    return conn.search(search_base=active_base_dn, search_filter=search_filter,
                       attributes=ALL_ATTRIBUTES)


def dn_get(conn, username):
    mydn = ''
    mail=''
    users_get(conn)
    if conn.entries:
        for entry in conn.entries:
            if username == entry.cn:
                mydn = entry.entry_dn
                mail=entry.mail.value
                break
        return mydn

def mail_get(conn, username):
    mydn = ''
    mail=''
    users_get(conn)
    if conn.entries:
        for entry in conn.entries:
            if username == entry.cn:
                # mydn = entry.entry_dn
                mail=entry.mail.value
                break
        return mail
