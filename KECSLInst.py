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

    def eccpukauth_initkeyeccobj():
        pyelliptic.ECC(pubkey=base64.b64decode(InstConf['Autheccpuk']),privkey=base64.b64decode(InstConf['Autheccpvk']),curve='secp521r1')
        pass
        

    def eccpukauth_makechallenge():
        challenge={}
        challengebody={}
        challengebody['auth_uuid']=uuid.uuid4()
        challengebody['auth_time']=time.time()
        Runtimevar['auth_time']=time.time()
        challengebody['auth_provider_uuid']=Runtimevar['uuid']
        challJSON=json.dumps(challengebody)
        challJSONb64=base64.b64encode(challJSON.encode('utf8'))
        challenge['signobj']=challJSONb64
        challenge['type']='eccpuk'
        challengeJSON=json.dumps(challenge)
        return challengeJSON
        
        
    def eccpukauth_verifychallenge(signrespJSON):
        if Runtimevar['auth_time'] + 30 > time.time():
            return False

        signresp=json.loads(signrespJSON)

        Rkeyb64=Runtimevar['callback_GetEccPukByID'](signresp['signor'])   
        if Rkeyb64 is not None:
            Rkey=base64.b64decode(Rkeyb64)
            signedobj=base64.b64decode(signresp['signedobj'])
            result=pyelliptic.ECC(publickey=Rkey).verify(signedobj,Runtimevar['challengebody'],curve='secp521r1')
            return result


        

    def eccpukauth_finishchallenge(challengeJSON):
        challenge=json.loads(challengeJSON)

        if challenge['type']==InstConf['authmode']:
            try:
                challJSONb64=challenge['signobj']
                challJSON=base64.b64decode(challJSONb64).decode('utf8')
                chall=json.loads(challJSON)
                if chall['auth_provider_uuid']==Runtimevar['Ruuid']:
                    if  not (chall['time']>=time.time()+30 and chall['time']<=time.time()-20):
                        sigureb=bRuntimevar['eccauthobj'].sign(base64.b64decode(challJSONb64))
                        sigureb64=base64.b64encode(sigureb)
                        signresp={}
                        signresp['signedobj']=sigureb64
                        signresp['signor']=InstConf['authas']
                        signrespJSON=json.dumps(signresp)
                        return signrespJSON

                        

            except Exception:
                pass
            else:
                pass

    def passwdauth_makechallenge(challenge):
        challenge={}
        challengebody={}
        challengebody['auth_uuid']=uuid.uuid4()
        challengebody['auth_time']=time.time()
        challengebody['auth_provider_uuid']=Runtimevar['uuid']
        challb=json.dumps(challengebody)
        Runtimevar['challengebody']=challb.encode('utf8')
        challb64=base64.b64encode(challb.encode('utf8'))
        challenge['signobj']=challb64
        challenge['type']='passwd'
        challengeJSON=json.dumps(challenge)
        return challengeJSON
        

    def passwdauth_verifychallenge(challenge):
        if Runtimevar['auth_time'] + 30 > time.time():
            return False

        signresp=json.loads(signrespJSON)

        Rkeyb64=Runtimevar['callback_GetPasswdHashByID'](signresp['signor'])   
        if Rkeyb64 is not None:
            Rkey=base64.b64decode(Rkeyb64)
            signedobj=base64.b64decode(signresp['signedobj'])
            signingobjhash=sha512(base64.b64decode(challJSONb64)).hexdigest()
            localpwdobjhash=InstConf['passwdhash']
            finalingtohash=''

            for i in range(0,len(signingobjhash)-1):
                finalingtohash += signingobjhash[i] + localpwdobjhash[i]

            reqsig=sha512(finalingtohash.encode('utf8')).hexdigest()
            incomingobj=signedobj.decode('utf8')
            if reqsig==incomingobj:
                return True
            else:
                return False



    def passwdauth_finishchallenge(challengeJSON):
        challenge=json.loads(challengeJSON)

        if challenge['type']==InstConf['authmode']:
            try:
                challJSONb64=challenge['signobj']
                challJSON=base64.b64decode(challJSONb64).decode('utf8')
                chall=json.loads(challJSON)
                if chall['auth_provider_uuid']==Runtimevar['Ruuid']:
                    if not(chall['time']>=time.time()+30 and chall['time']<=time.time()-20):
                        
                        signingobjhash=sha512(base64.b64decode(challJSONb64)).hexdigest()
                        localpwdobjhash=InstConf['passwdhash']
                        finalingtohash=''

                        for i in range(0,len(signingobjhash)-1):
                            finalingtohash += signingobjhash[i] + localpwdobjhash[i]

                        sigureb=sha512(finalingtohash.encode('utf8')).hexdigest()

                        sigureb64=base64.b64encode(sigureb)
                        signresp={}
                        signresp['signedobj']=sigureb64
                        signresp['signor']=InstConf['authas']
                        signrespJSON=json.dumps(signresp)
                        return signrespJSON

                        

            except Exception:
                pass
            else:
                pass

    def kecsl_makeconnreq():
        connreq={}
        connreq['reqeruuid']=Runtimevar['uuid']
        connreq['reqerpuk']=InstConf['Leccpuk']
        connreq['time']=time.time()
        connreq['authmode']=InstConf['authmode']
        return connreq


        

    def kecsl_progressconnreq(req):
        Runtimevar['Ruuid']=req['reqeruuid']
        Runtimevar['Reccpuk']=req['reqerpuk']

    def kecsl_checkconnreq(req):
        if req['time']+30<time.time() or req['time']-30>time.time():
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
        Runtimevar['Rauthmode']=connreq['authmode']
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
        Runtimevar['Conneccobj']=pyelliptic.ECC(pubkey=base64.b64decode(InstConf['Leccpuk']),privkey=base64.b64decode(InstConf['Leccpvk'],curve='secp521r1'))

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
        if kecsl_isrereceive(data)==0:
            datadecsl=kecsl_decsl(data)
            return True,datadecsl

        else:
            return False,Runtimevar['lastsent']

    def kecsl_resend():
        if Runtimevar['Lnxtiv']!="":
            return None
        else:
            return Runtimevar["lastsent"]

    def auth_makeauthresult(res):
        retv=''
        if res:
            retv="Succ"
        else:
            retv='Err' 
        authresult={}
        authresult['stat']=retv
        
        return kecsl_encsl(json.dumps(authresult))

    def auth_checkauthresult(rescsl):
        authresult=json.loads(kecsl_encsl(rescsl))
        if authresult['stat']=='Succ':
            return True
        else:
            return False


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
                return self.kecsl_makeconn(data)

    def OnRecvConnectReq(self,data):
        return self.kecsl_recvconn(data)

    def Send(self,data):
        return self.kecsl_send(data)

    def Resend(self):
        return self.kecsl_resend()

    def OnReceive(self,data):
        return self.kecsl_receive(data)

    def AskforAuth(self):
        if self.Runtimevar['Rauthmode']=='eccpuk':
            challenge=eccpukauth_makechallenge()


        if self.Runtimevar['Rauthmode']=='passwd':
            challenge=passwdauth_makechallenge()

        challengecsl=kecsl_encsl(challenge)
        return challengecsl

    def OnAskForAuth(self,datacsl):
        data=kecsl_decsl(datacsl)
        Authd=json.loads(data)
        if self.Runtimevar['authmode']=='eccpuk':
            challenge=eccpukauth_finishchallenge(Authd)


        if self.Runtimevar['authmode']=='passwd':
            challenge=passwdauth_finishchallenge(Authd)

        challengedcsl=kecsl_encsl(challenge)
        return challengedcsl

    def OnReceiveAuth(self,datacsl):
        data=kecsl_decsl(datacsl)
        Authd=json.loads(data)
        if self.Runtimevar['authmode']=='eccpuk':
            result=eccpukauth_verifychallenge(Authd)


        if self.Runtimevar['authmode']=='passwd':
            result=passwdauth_verifychallenge(Authd)

        
        return result,self.auth_makeauthresult(result)

    def OnReceiveAuthReply(self,datacsl):
        return self.auth_checkauthresult(datacsl)
        