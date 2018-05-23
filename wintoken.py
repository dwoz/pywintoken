""" Lists various types of information about current user's access token,
    including UAC status on Vista
"""

import pywintypes, win32api, win32security
import win32con, winerror
from _wintoken_security_enums import TOKEN_GROUP_ATTRIBUTES, TOKEN_PRIVILEGE_ATTRIBUTES, \
     SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, TOKEN_ELEVATION_TYPE


def token_info(th):
    token_info = []
    token_type=win32security.GetTokenInformation(th, win32security.TokenType)
    token_info.append(
        ('TokenType:', token_type, TOKEN_TYPE.lookup_name(token_type))
    )
    if token_type==win32security.TokenImpersonation:
        imp_lvl=win32security.GetTokenInformation(th, win32security.TokenImpersonationLevel)
        token_info.append(
            ('TokenImpersonationLevel:', imp_lvl, SECURITY_IMPERSONATION_LEVEL.lookup_name(imp_lvl))
        )
    token_info.append(
        token_info.append(('TokenSessionId:', win32security.GetTokenInformation(th, win32security.TokenSessionId)))
    )
    privs=win32security.GetTokenInformation(th,win32security.TokenPrivileges)
    token_info.append(('TokenPrivileges:',))
    for priv_luid, priv_flags in privs:
        flag_names, unk=TOKEN_PRIVILEGE_ATTRIBUTES.lookup_flags(priv_flags)
        flag_desc = ' '.join(flag_names)
        if (unk):
            flag_desc += '(' + str(unk) + ')'

        priv_name=win32security.LookupPrivilegeName('',priv_luid)
        priv_desc=win32security.LookupPrivilegeDisplayName('',priv_name)
        token_info.append(
            ('\t', priv_name, priv_desc, priv_flags, flag_desc,)
        )

    token_info.append(('TokenGroups:',))
    groups=win32security.GetTokenInformation(th,win32security.TokenGroups)
    for group_sid, group_attr in groups:
        flag_names, unk=TOKEN_GROUP_ATTRIBUTES.lookup_flags(group_attr)
        flag_desc = ' '.join(flag_names)
        if (unk):
            flag_desc += '(' + str(unk) + ')'
        if group_attr & TOKEN_GROUP_ATTRIBUTES.SE_GROUP_LOGON_ID:
            sid_desc = 'Logon sid'
        else:
            sid_desc=win32security.LookupAccountSid('',group_sid)
        token_info.append(
            ('\t',group_sid, sid_desc, group_attr, flag_desc,)
        )

    ## Vista token information types, will throw (87, 'GetTokenInformation', 'The parameter is incorrect.') on earier OS
    try:
        is_elevated=win32security.GetTokenInformation(th, win32security.TokenElevation)
        token_info.append(('TokenElevation:', is_elevated,))
    except pywintypes.error, details:
        if details.winerror != winerror.ERROR_INVALID_PARAMETER:
            raise
        return None
    token_info.append(
        ('TokenHasRestrictions:', win32security.GetTokenInformation(th, win32security.TokenHasRestrictions),)
    )
    token_info.append(
        ('TokenMandatoryPolicy', win32security.GetTokenInformation(th, win32security.TokenMandatoryPolicy),)
    )
    #print 'TokenIntegrityLevel', win32security.GetTokenInformation(th, win32security.TokenIntegrityLevel)
    token_info.append(
        ('TokenVirtualizationAllowed:', win32security.GetTokenInformation(th, win32security.TokenVirtualizationAllowed),)
    )
    token_info.append(
        ('TokenVirtualizationEnabled:', win32security.GetTokenInformation(th, win32security.TokenVirtualizationEnabled),)
    )

    elevation_type = win32security.GetTokenInformation(th, win32security.TokenElevationType)
    token_info.append(
        ('TokenElevationType:', elevation_type, TOKEN_ELEVATION_TYPE.lookup_name(elevation_type),)
    )
    return token_info


def dump_token(tk):
    info = token_info(tk)
    return '\n'.join([' '.join(x) for x in info])


def print_token(tk):
    print(dump_token(tk))
