#!/usr/bin/env python3
import uuid
import json
import time
import pyelliptic
import base64
import lzma
from hashlib import sha512

AuthMode={
'eccpuk', #ECC publickey
'passwd'  #password
}

ConnMode={
'ltn',  #Accepting Connection
'pst'   #Make Connection
}

class KKUniCtrlConsole_KECSLInst(object):
    """docstring for KKUniCtrlConsole_KECSLInst"""
    def __init__(self):
        super(KKUniCtrlConsole_KECSLInst, self).__init__()
        
    InstConf={}
    Runtimevar={}

    def SetConfig(self,key,val):
        self.InstConf[key]=val

    def GetConfig(self,key):
        if key in self.InstConf:
            return self.InstConf[key]
        else:
            raise Exception("Not exist.")

    def LoadConfig(self,confDict):
        self.InstConf.update(confDict)

    def InitConfig(self,connmode,authmode=None):
        if connmode in ConnMode:
            if connmode == "ltn":
                pass


            if connmode == "pst":
                if authmode in AuthMode:
                    if authmode == "eccpuk":
                        pass


                    if authmode == "passwd":
                        pass
                    
                    InstConf['Reccpuk']=''
                    InstConf['authmode']=authmode
                else:
                    raise Exception("Unknown authmode.")
            InstConf['Leccpuk']=''
            InstConf['Leccpvk']=''
            InstConf['connmode']=connmode
        else:
            raise Exception("Unknown connmode.")



    def eccpukauth_genkey():
        pyelliptic.ECC(curve='secp521r1')
        InstConf['Autheccpuk']=base64.b64encode(pyelliptic.get_pubkey())
        InstConf['Autheccpvk']=base64.b64encode(pyelliptic.get_privkey())
        

    def eccpukauth_makechallenge():
        pass
        
    def eccpukauth_verifychallenge():
        pass

    def eccpukauth_finishchallenge():
        pass

    def passwdauth_makechallenge():
        pass

    def passwdauth_verifychallenge():
        pass

    def passwdauth_finishchallenge():
        pass

    def kecsl_makeconnreq():
        connreq={}
        connreq['reqeruuid']=Runtimevar['uuid']
        connreq['reqerpuk']=InstConf['Leccpuk']
        connreq['time']=time.time()


        

    def kecsl_progressconnreq(req):
        Runtimevar['Ruuid']=req['reqeruuid']
        Runtimevar['Reccpuk']=req['reqerpuk']

    def kecsl_checkconnreq(req):
        if req['time']+300<time.time() or req['time']-300>time.time():
            raise Exception("time sync error")
        else:
            Runtimevar['timeoffset']=time.time()-req['time']


    def kecsl_genkey():
        pyelliptic.ECC(curve='secp521r1')
        InstConf['Leccpuk']=base64.b64encode(pyelliptic.get_pubkey())
        InstConf['Leccpvk']=base64.b64encode(pyelliptic.get_privkey())

    def kecsl_makerecvconnresp(connreq):
        recvconnresp={}
        recvconnresp['Stat']='Succ'
        Runtimevar['Lnxtiv']=pyelliptic.Cipher.gen_IV('aes-256-cfb')
        Runtimevar['ivlen']=len(Runtimevar['Lnxtiv'])
        recvconnresp['nxtiv']=base64.b64encode(Runtimevar['Lnxtiv'])
        Runtimevar['cslskey']=sha512(os.urandom(65536))
        recvconnresp['key']=base64.b64encode(recvconnresp['key'])
        recvconnresp['Cnduuid']=Runtimevar['uuid']
        return recvconnresp

    def kecsl_progrecvconnresp(recvconnresp):
        if recvconnresp['Stat']=='Succ':
            Runtimevar['ivlen']=len(recvconnresp['nxtiv'])
            Runtimevar['Rnxtiv']=base64.b64decode(recvconnresp['nxtiv'])
            Runtimevar['cslskey']=base64.b64decode(Runtimevar['cslskey'])
            Runtimevar['Ruuid']=recvconnresp['Cnduuid']
            return 1

        else:
            raise Exception("Remote respond show non-Succ resp")

    def kecsl_decslob(data):
        decer=pyelliptic.Cipher(Runtimevar['cslskey'], Runtimevar['Lnxtiv'], 0, ciphername='aes-256-cfb')
        Runtimevar['Rlstiv']=Runtimevar['Rnxtiv']
        Runtimevar['Rnxtiv']=''
        cslobl=decer.ciphering(data)
        cslob=lzma.decompress(cslobl,format=lzma.FORMAT_ALONE)
        Runtimevar['Rnxtiv']=cslob[:Runtimevar['ivlen']]
        cslo=cslob[Runtimevar['ivlen']:]
        return cslo


    def kecsl_encslob(data):
        if Runtimevar['Rnxtiv'] == "":
            raise Exception("no ack")
        cslob=data
        Runtimevar['Lnxtiv']=pyelliptic.Cipher.gen_IV('aes-256-cfb')
        cslob=Runtimevar['Lnxtiv']+cslob
        cslobl=lzma.compress(cslob,format=lzma.FORMAT_ALONE)
        encer=pyelliptic.Cipher(Runtimevar['cslskey'],Runtimevar['Rnxtiv'],1,ciphername='aes-256-cfb')
        Runtimevar['Rlstiv']=Runtimevar['Rnxtiv']
        Runtimevar['Rnxtiv']=''
        cslobole=encer.ciphering(cslobl)
        return cslobole




    def kecsl_recvconn(connreqcsl):
        try:

            connreqJSON=kecsl_decsl(connreqJSONble)
            connreq=json.loads(connreq)
            kecsl_checkconnreq(connreq)
            kecsl_progressconnreq(connreq)
            connresp=kecsl_makerecvconnresp(connreq)
            connrespcsl=kecsl_encsl(json.dumps(connresp))
            return connrespcsl
        except Exception:
            pass
        else:
            pass

    def kecsl_isrereceive(data):
        thishash=sha512(data)
        if thishash==Runtimevar['lastrecv512']:
            return 1
        else:
            Runtimevar['lastrecv512']=sha512(data)
            return 0

        

    def kecsl_recvconnresp(connrespcsl):
        try:
            connrespJSON=kecsl_decsl(connrespcsl)
            connresp=json.loads(connrespJSON)
            return kecsl_progrecvconnresp(connresp)
        except Exception:
            pass
        else:
            pass

    def kecsl_decsl(data):
        cslbl=Runtimevar['Conneccobj'].decrypt(data)
        cslb=lzma.decompress(cslbl,format=lzma.FORMAT_ALONE)
        csl==cslb.decode('utf8')
        return csl
        

    def kecsl_encsl(data):

        cslb=data.encode('utf8')
        cslbl=lzma.compress(cslb,format=lzma.FORMAT_ALONE)
        cslble=Runtimevar['Conneccobj'].encrypt(cslbl,base64.b64decode(InstConf['Reccpuk']))
        return cslble
        

    def kecsl_makeconn():
        connreq=kecsl_makeconnreq()
        connreqJSON=json.dumps(connreq)
        connreqJSONcsl=kecsl_encsl(connreqJSON)
        return connreqJSONcsl

    def kecsl_initeccobj():
        Runtimevar['Conneccobj']=pyelliptic.ECC(pubkey=base64.b64decode(InstConf['Leccpuk']),privkey=base64.b64decode(InstConf['Leccpvk']))

    def InitRuntime(self):
        self.Runtimevar['uuid']=str(uuid.uuid4())
        self.Runtimevar['Rnxtiv'] == ""
        self.Runtimevar['Lnxtiv'] == ""

    def kecsl_send(data):
        if Runtimevar['Lnxtiv']=="":
            raise Exception('No successful ack')

        datacsl=kecsl_encslob(data)
        Runtimevar["lastsent"]=datacsl
        return datacsl

    def kecsl_receive(data):
        if !kecsl_isrereceive(data):
            datadecsl=kecsl_decsl(data)
            return datadecsl

        else:
            return None

    def kecsl_resend():
        if Runtimevar['Lnxtiv']!="":
            return None
        else:
            return Runtimevar["lastsent"]

    def Connect(self):
        if self.InstConf['connmode']!="pst":
            if self.Runtimevar['uuid']=="":
                if self.Runtimevar['Ruuid']!="":
                    return self.kecsl_makeconn()
                else:
                    raise Exception('Already Connected')
            else:
                raise Exception('Runtime not inited.')
                
        else:
            raise Exception("Mode is not pst, should wait for Connection")

    def OnConnect(self,data):
        if self.InstConf['connmode']=="ltn":
            if self.Runtimevar['Ruuid']=="":
                return self.kecsl_recvconn(data)

    def OnRecvConnectReq(self,data):
        return self.kecsl_recvconn(data)

    def Send(self,data):
        return self.kecsl_send(data)

    def Resend(self):
        return self.kecsl_resend()

    def OnReceive(self,data):
        return self.kecsl_receive(data)


