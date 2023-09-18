# read (PowerMTA PMTA) acct-*.csv file and parse bounce emails based on their status and error messages!

# Author: Janib Soomro <soomrojb@gmail.com>

from re import sub
import pandas as pd
from glob import glob
from csv import writer
from datetime import datetime

today_date = datetime.now()
chunk_size = 10000

input_path = "acct-*.csv"
bounce_patterns = ['Addressee unknown','Recipient not recognised','RecipientNotFound','does not exist','mailbox unavailable','invalid address','dosn\'t exist','mailbox is disabled','mailbox not found','quota and inactive','Unrouteable address','No such user','tried to reach does not exist','domain may not exist','recipient is not exist','User not found','invalid recipient','not exist here','no valid recipient','find the recipient domain','mailbox is full','don\'t handle mail for','this address is no longer active','not handle mail for','not in use and does not accept mail','not available here','Bad destination mailbox address','no mailbox here by that name','Addressee unknown,','No such address: <','> is not a valid mailbox','Email address could not be found,','Recipient verify failed','accept mail to this address','Unroutable address','mailhost - invalid address','This domain is not hosted here','No account by that name here','Usuario Desconocido','address no longer accepts mail','No such domain at this location','No such person at this address','permanent failure for one or more recipients','no mailbox by that name is currently available','Not our Customer','unknown ;id=','No such recipient','invalid mailbox','not a valid mailbox','address could not be found','can\'t verify recipient','Unable to relay for','Recipient unknown','Mailbox doesn\'t exist','Account disabled','esta en estado: inactivo','account expired','is not a valid user','Address not present in directory','Address unknown','user invalid','Not Known to us. Do not resend','E-mail address is not handled by this system','This person has departed','Not authorised for direct delivery to this host','recipient not found','> recipient rejected','is over quota','Mailbox full','limit exceeded','unable to verify user','does not exist here','> User unknown','Account Inactive','recipient does not exist','user quota exceeded','the mailbox is unavailable','Recipient overquota','rejected: over quota','Mail quota exceeded','exceeded storage allocation','Domain not found','user disabled','User Not Exist','User suspended:','unknown user','Unknown Email Address','email address does not exist','no such address here','Blocks limit exceeded','Inode limit exceeded','>... Relaying denied','>... User unknown','Could not load DRD for domain','>: Recipient address rejected: Unknown Address','Recipient address rejected: undeliverable address','Webmail has been discontinued','This mailbox has been blocked due to inactivity',': User unknown','> unknown recipient','5.1.1 User unknown','No mail box available for this user','email account that you tried to reach is disabled']
dsnstatus_pattern = ['unable to route: dns lookup failure','unable to route: no mail hosts for domain','bad destination system: no such domain','routing loop detected','Recipient address has null MX','Helo command rejected: Host not found']
false_positive = ['due to policy restriction']
output_file = f"bounces{today_date.strftime('-%M-%m-%d-%Y')}.csv" 
not_bounces = ['badmailfrom list', 'ptr record setup', 'network is on our block list', 'an rbl', 'spamhaus', 'niftygreeting connections limit exceeded', 'dns check failed', 'too many invalid recipients', 'poor reputation', 'accept mails from your IP address', 'blacklisted using', 'not relaying for', 'as a relay,', 'JunkMail rejected', 'is in a black list', 'Relay access denied', 'Access denied', 'rejected due to', 'rejected under suspicion', 'RBL match', 'relaying blocked,', 'blocked using', 'refused by', 'not allowed to connect', 'sending spam', 'ipcheck.proofpoint.com', 'poor reputation', 'Cloudmark', 'Spam content', 'security policie', 'bad reputation', 'Policy Violation', 'cloudfilter.net', 'by behaviour', 'postmaster.comcast.net', 'DNSBLs', 'content spam', 'barracudanetworks', 'Relaying denied', 'abuse_rbl', 'RBL Restriction', 'abusix.com','All recipient addresses rejected', 'unexpected volume', 'turn on SMTP Authentication', 'your IP address', 'rejected by the system', 'the sender IP found', 'denylisted', 'SpamTrap', 'blocked by', 'server requires authentication', 'has detected that', 'likely suspicious', 'AntiSpam', 'blocked IP', 'protect our users', 'blacklisted', 'sophos.com', 'low reputation', 'abuse team', 'spam filter', 'IP Blocked', 'much spam', 'anti-spam', 'Spam message', 'como spam', 'bloqueado', 'spamrl.com', 'like SPAM', 'consider spam.', 'on spam scale', 'as spam and', 'IP has been rejected', 'is blocklisted by', 'as spam', 'considered spam', 'probability of spam', 'due to Spam', 'DNS blacklist', 'likely blacklist', '- blacklist -', 'RBL Blacklist', 'is listed in', 'de SPAM', 'STOP SPAM', 'spam reject', 'SPAM-like', 'to be spam', 'spam detect', 'REJECT spam', 'SpamAssassin', 'barracudacentral', 'dnsbl.sorbs.net', 'rspamd filter', 'spam blocked', 'suspected spam', 'is listed as', 'postmaster.specialist', 'NOSPAMTAG', 'mail de IP', 'detected as SPAM', 'em blacklist', 'in Abusix', 'forbidden by your', 'header are not accepted.', 'reputation score of', 'IP address is block listed', 'our block list', 'as abusive', 'IP Block-listed', 'dnsbl-lookup', 'esta em lista negra', 'score too low', 'high-probability spam', 'spamcop', 'Spam email.', 'potencial spam', 'antyspamowa', 'it is spam', 'esta listado', 'blocked for security reasons', '- spam', 'reducing spam', 'origin of SPAM', 'possible spam', 'spam points', 'Reputation too low', 'rbl.securence', 'transient IP not allowed', 'your senderbase score', 'BLOCKLIST', 'unsolicited email', 'Bad DNS PTR', 'been prevented from', 'G_MAX_BAD_IP', 'all recipients were rejected', 'rate limit exceeded', 'unable to route: no mail hosts for domain', 'no answer from host', 'delivery not authorized', 'system not accepting network messages']
replace_regex = [['\"',''], [r'\s+access\s+denied\s+\[m.+$','access denied'], [r'.\s+http://.+$','.'], [r'&quote;',''], [r'requested\s+mail\s+action\s+aborted,\s+mailbox\s+not\s+found.+$','Mailbox not found'], [r'requested\s+mail\s+action\s+aborted,\s+mailbox\s+not\s+found.+$','Mailbox not found'], [r'.\s+or\s+perhaps\s+your\s+address\s+is\s+not.+$',''], [r'\s+unknown\s+in\s+virtual\s+alias\s+table.+','unknown in virtual alias table'], [r':\s+undeliverable\s+address:.+$',': undeliverable address'], [r'\s+or\s+see\s+https:',''], [r'unknown\s+in\s+virtual\s+mailbox\s+table.+',''], [r'unknown\s+-\s+for help.+','unknown'], [r'.\s+for\s+assistance,.+',''], [r'k.+\s+adresse\s+d\s+au\s+moins\s+un\s+destinataire\s+invalide.\s+invalid\s+recipient.\s+ofr_.+$','Invalid recipient'], [r'mx.+\smailbox\s+.+\s+unknown\s+;.+$','Mailbox unknown'], [r'no\s+such\s+user\s+\+.+$','No such user'], [r'the\s+email\s+account\s+that\s+you\s+tried\s+to\s+reach\s+does\s+not\s+exist.\s+please\s+try.+$','The email account that you tried to reach does not exist.'], [r'.\s+please\s+try\s+double-checking.+$','.'], [r'RCPT\s+TO\s+mailbox\s+unavailable.+$','Mailbox unavailable'], [r'resolver.adr.recipientnotfound;\s+recipient\s+not\s+found\s+by.+','Recipient not found'], [r'reach\s+is\s+disabled.\s+Learn more\s+.+$','reach is disabled.'], [r'Mailbox\s+size\s+limit\s+exceeded\s+16\d+.+$','Mailbox size limit exceeded'], [r'quota\s+and\s+inactive.\s+Please\s+direct.+', 'quota and inactive.'], [r'.\s+For\s+explanation\s+visit.+$','.'], [r'.\s+Please\s+visit.+$', '.'], [r'mailbox\s+unavailable\s+\(S.+$', 'mailbox unavailable'], [r'.\s+However,\s+if\s+you.+$', '.'], [r'No\s+such\s+user!\s+1\d+.+$', 'No such user!'], [r'.\s+Please\s+direct\s+the.+$', '.'], [r'\s+\[Support\s+Info.+$', ''], [r'permanent\s+failure\s+for\s+one\s+or\s+more\s+recipients\s+\(.+$', 'permanent failure for one or more recipients'], [r':\s+unverified\s+address:.+$', ': unverified address'], [r'\s+Please\s+see.+$', ''], [r';\s+If\s+you\s+need\s+help,.+$', ''], [r'smtp;550\s+The\s+mail\s+server\s+could\s+not\s+deliver\s+mail\s+to\s+.+$', 'smtp;550 The mail server could not deliver mail'], [r'recipient\s+table\s+Para.+$', 'recipient table'], [r'.\s+Please\s+direct\s+the\s+recipient.+$', '.'], [r'smtp;452\s+4.2.2\s+The\s+email\s+account\s+that\s+you\s+tried\s+to\s+reach\s+is\s+over\s+quota.+$', 'smtp;452 4.2.2 Mailbox full'], [r'.\s+Please\s+direct;.+$', '.'], [r'inactive.;+$', ''], [r'.\s+Local\s+mailbox\s+.+$', '.'], [r'\s+\(S2\d+.+$', ''], [r'denied\s+\[MA.+$', 'denied'], [r'not\s+exist\s+-\s+https:.+$', 'not exist'], [r'\s+;id=.+$', ''], [r'smtp;550\s+5.1.1\s+No\s+such\s+user\s+.+$', 'smtp;550 5.1.1 No such user'], [r'Specified\s+domain\s+is\s+not\s+allowed\(.+\)\s+', ''], [r'denied.\s+AS\(2.+', 'denied.'], [r'.\s+Learn\s+more\s+at\s+https.+$', '.'], [r'\.\s+Learn\s+more\s+at.+$',''], [r'\s+<http.+$',''], [r'\s+-\s+http.+$',''], [r'\.\s+Please\s+try.+$',''], [r'\s+\[\s+7.+$',''], [r'\s+-ERR\s+.+$',''], [r'\s+longer\s+available\s+https.+$',''], [r'\s+<.+>:\s+.+\s+sorry,\s+no\s+mailbox\s+here.+$','no mailbox here'], [r'\s+Sorry,\s+your\s+message\s+to\s+.+\s+cannot\s+be\s+delivered.\s+This\s+mailbox\s+is\s+disabled.+$',' Mailbox disabled.'], [r'>\s+\[InternalId=.+$','>'], [r'\.\s+For\s+more\s+.+$', '.'], [r'\s+.For\s+more\s+.+$',''], [r'\s+Please\s+call\s+.+$',''], [r'\s+accept\s+mail\s+\(.+$',''], [r'\s+OK\s+.+\s+-\s+gsmtp', ' OK'], ['\.\s+OR\s+perhaps\s+YOUR.+$',''], [r'\s+For\s+assistance\s+.+$,',''], [r'relay\s+recipient\s+table\s+.+$',''], [r'\s+Please\s+check\s+the\s+spelling\s.+$',''], [r'\s+Please\s+contact\s+your.+$',''], [r'\s+Aide\/.+$',''], [r'.\s+Refer\s+to\s+the\s+Troubleshooting.+$',''], [r'Desculpe,\s+nao\s+.+\s+\(sorry,\s+no\s+mailbox\s+here\s+by\s+that\s+name\..+$', 'No mailbox'], [r'\s+For\s+assistance,\s+contact\s+.+$',''], [r'\s+---\s+Contact\s+your\s+.+$',''], [r'\s+The\s+error\s+that\s+.+$',''], [r'.\s+Please\s+check\s+.+$',''], [r'.\s+Please\s+provide\s+.+$',''], [r'<Qdmail\.+>\.\.\.\s+User unknown, not local address.+$', 'User unknown, not local address'] ]
all_bounces = {}

def check_false_positive(mystring):
    flag = False
    newstring = mystring.lower()
    for x in false_positive:
        if x.lower() in newstring:
            flag = True
            break
    return flag

for accfile in glob(input_path):
    print (f"Processing: {accfile}")
    # df = pd.read_csv(accfile,low_memory=False)
    
    tfr = pd.read_csv(accfile, chunksize=chunk_size, iterator=True)
    df = pd.concat(tfr, ignore_index=True)

    email = df['rcpt']
    dsnstatus = df['dsnStatus']
    dsndiag = df['dsnDiag']
    dlvdestip = df['dlvDestinationIp']
    i = -1
    for l in dsndiag:
        i += 1
        if not any(x.lower() in str(l).lower() for x in not_bounces):
            flag = False
            _email = str(email[i]).lower()
            if not _email in all_bounces:
                if flag == False:
                    l_dsndiag = str(l).lower()
                    for bp in bounce_patterns:
                        if bp.lower() in l_dsndiag:
                            # ensure there are no false-positives
                            if check_false_positive(l_dsndiag) == False:
                                all_bounces[_email] = ["Hard",dsnstatus[i],l]
                                flag = True
                            break
                if flag == False:
                    l_dsnstatus = str(dsnstatus[i]).lower()
                    for dsp in dsnstatus_pattern:
                        if dsp.lower() in l_dsnstatus:
                            all_bounces[_email] = ["Soft",dsnstatus[i],l]
                            flag = True
                            break
                if flag == False:
                    # destination server IP missing
                    if len(dlvdestip) < 2:
                        all_bounces[_email] = ["Hard",dsnstatus[i],dsndiag[i]]
                        flag = True
                        break

if len(all_bounces) > 0:
    outputf = open(output_file, "w")
    for r in all_bounces:
        bounce_reason = all_bounces[r][2]
        for rp in replace_regex:
            bounce_reason = sub( rp[0], rp[1], str(bounce_reason) )
        outputf.write(f""""{r}","{all_bounces[r][0]}","{all_bounces[r][1]}","{bounce_reason}"\n""")
    outputf.close()

print ("Done!")
