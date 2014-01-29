#!/usr/bin/env python3
import uuid
import json
import time
import pyelliptic
import base64
import lzma
from hashlib import sha512
import os

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
        self.InstConf=confDict

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
                    
                    self.InstConf['Reccpuk']=''
                    self.InstConf['authmode']=authmode
                else:
                    raise Exception("Unknown authmode.")
            self.InstConf['Leccpuk']=''
            self.InstConf['Leccpvk']=''
            self.InstConf['connmode']=connmode
        else:
            raise Exception("Unknown connmode.")

    def ExportConfig(self):
        return self.InstConf

    def eccpukauth_genkey(self):
        ecckeyobj=pyelliptic.ECC(curve='secp521r1')
        self.InstConf['Autheccpuk']=base64.b64encode(ecckeyobj.get_pubkey()).decode("utf-8")
        self.InstConf['Autheccpvk']=base64.b64encode(ecckeyobj.get_privkey()).decode("utf-8")

    def eccpukauth_initkeyeccobj(self):
        if self.InstConf['Autheccpuk'] =='' or self.InstConf['Autheccpvk']=='':
            raise Exception('eccpukauth key not set')
        
        

    def eccpukauth_makechallenge(self):
        challenge={}
        challengebody={}
        challengebody['auth_uuid']=str(uuid.uuid4())
        challengebody['auth_time']=time.time()
        self.Runtimevar['auth_time']=time.time()
        challengebody['auth_provider_uuid']=self.Runtimevar['uuid']
        challJSON=json.dumps(challengebody)
        self.Runtimevar['challengebody']=challJSON
        challJSONb64=base64.b64encode(challJSON.encode('utf8')).decode("utf-8")
        challenge['signobj']=challJSONb64
        challenge['type']='eccpuk'
        challengeJSON=json.dumps(challenge)
        return challengeJSON
        
        
    def eccpukauth_verifychallenge(self,signresp):
        if self.Runtimevar['auth_time'] + 30 < time.time():
            return False

        

        Rkeyb64=self.Runtimevar['callback_GetEccPukByID'](signresp['signor'])   
        
        if Rkeyb64 is not None:
            Rkey=base64.b64decode(Rkeyb64.encode('utf8'))
            signedobj=base64.b64decode(signresp['signedobj'])
            result=pyelliptic.ECC(pubkey=Rkey,curve='secp521r1').verify(signedobj,self.Runtimevar['challengebody'].encode('utf8'))
            if result:
                return signresp['signor']
            else:
                False


        

    def eccpukauth_finishchallenge(self,challenge):
        eccauthobj=pyelliptic.ECC(pubkey=base64.b64decode(self.InstConf['Autheccpuk'].encode('utf8')),privkey=base64.b64decode(self.InstConf['Autheccpvk'].encode('utf8')),curve='secp521r1')

        if challenge['type']==self.InstConf['authmode']:
            try:
                challJSONb64=challenge['signobj']
                challJSON=base64.b64decode(challJSONb64).decode('utf8')
                chall=json.loads(challJSON)
                if chall['auth_provider_uuid']==self.Runtimevar['Ruuid']:
                    if  not (chall['auth_time']>=time.time()+30 and chall['auth_time']<=time.time()-20):
                        sigureb=eccauthobj.sign(base64.b64decode(challJSONb64.encode('utf8')))
                        sigureb64=base64.b64encode(sigureb).decode("utf-8")
                        signresp={}
                        signresp['signedobj']=sigureb64
                        signresp['signor']=self.InstConf['authas']
                        signrespJSON=json.dumps(signresp)
                        return signrespJSON

                        

            except Exception :
                pass
            else:
                pass

    def passwdauth_makechallenge(self):
        challenge={}
        challengebody={}
        challengebody['auth_uuid']=str(uuid.uuid4())
        challengebody['auth_time']=time.time()
        self.Runtimevar['auth_time']=challengebody['auth_time']
        challengebody['auth_provider_uuid']=str(self.Runtimevar['uuid'])
        challb=json.dumps(challengebody)
        self.Runtimevar['challengebody']=challb.encode('utf8')
        challb64=base64.b64encode(challb.encode('utf8')).decode("utf-8")
        challenge['signobj']=challb64
        challenge['type']='passwd'
        challengeJSON=json.dumps(challenge)
        return challengeJSON
        

    def passwdauth_makebund(self,signobjb64,passwdhash):
        signingobjhash=sha512(signobjb64).hexdigest()
        localpwdobjhash=passwdhash
        finalingtohash=''

        for i in range(0,len(signingobjhash)-1):
            finalingtohash += signingobjhash[i] + localpwdobjhash[i]

        sigureb=sha512(finalingtohash.encode('utf8')).hexdigest()

        return sigureb

    def passwdauth_verifychallenge(self,signresp):
        if self.Runtimevar['auth_time'] +30 < time.time():
            return False

        

        keyhash=self.Runtimevar['callback_GetPasswdHashByID'](signresp['signor'])   
        if keyhash is not None:
            incomingobj=signresp['signedobj']
            reqsig=self.passwdauth_makebund(self.Runtimevar['challengebody'],keyhash)
            if reqsig==incomingobj:
                return signresp['signor']
            else:
                return False



    def passwdauth_finishchallenge(self,challenge):

        if challenge['type']==self.InstConf['authmode']:
            try:
                challJSONb64=challenge['signobj']
                challJSON=base64.b64decode(challJSONb64).decode('utf8')
                chall=json.loads(challJSON)
                if chall['auth_provider_uuid']==self.Runtimevar['Ruuid']:
                    if not(chall['auth_time']>=time.time()+30 and chall['auth_time']<=time.time()-20):
                        
                        localpwdobjhash=self.InstConf['passwdhash']
                        sigureb=self.passwdauth_makebund(base64.b64decode(challJSONb64),localpwdobjhash)
                        signresp={}
                        signresp['signedobj']=sigureb
                        signresp['signor']=self.InstConf['authas']
                        signrespJSON=json.dumps(signresp)
                        return signrespJSON

                        

            except Exception:
                pass
            else:
                pass

    def kecsl_makeconnreq(self):
        connreq={}
        connreq['reqeruuid']=self.Runtimevar['uuid']
        connreq['reqerpuk']=self.InstConf['Leccpuk']
        connreq['time']=time.time()
        connreq['authmode']=self.InstConf['authmode']
        return connreq


        

    def kecsl_progressconnreq(self,req):
        self.Runtimevar['Ruuid']=req['reqeruuid']
        self.Runtimevar['Reccpuk']=req['reqerpuk']

    def kecsl_checkconnreq(self,req):
        if req['time']+30<time.time() or req['time']-30>time.time():
            raise Exception("time sync error")
        else:
            self.Runtimevar['timeoffset']=time.time()-req['time']


    def kecsl_genkey(self):
        genedecc=pyelliptic.ECC(curve='secp521r1')
        self.InstConf['Leccpuk']=base64.b64encode(genedecc.get_pubkey()).decode("utf-8")
        self.InstConf['Leccpvk']=base64.b64encode(genedecc.get_privkey()).decode("utf-8")

    def kecsl_makerecvconnresp(self,connreq):
        recvconnresp={}
        recvconnresp['Stat']='Succ'
        self.Runtimevar['cslskey']=sha512(os.urandom(65536)).digest()
        recvconnresp['key']=base64.b64encode(self.Runtimevar['cslskey']).decode("utf-8")
        recvconnresp['Cnduuid']=self.Runtimevar['uuid']
        self.Runtimevar['Rauthmode']=connreq['authmode']
        return recvconnresp

    def kecsl_progrecvconnresp(self,recvconnresp):
        if recvconnresp['Stat']=='Succ':
            
            
            self.Runtimevar['cslskey']=base64.b64decode(recvconnresp['key'].encode('utf8'))
            self.Runtimevar['Ruuid']=recvconnresp['Cnduuid']
            return 1

        else:
            raise Exception("Remote respond show non-Succ resp")

    def kecsl_decslob(self,data):
        
        iv=data[:pyelliptic.Cipher.get_blocksize('aes-256-cfb')]
        decer=pyelliptic.Cipher(self.Runtimevar['cslskey'], iv, 0, ciphername='aes-256-cfb')
        cslobl=decer.ciphering(data[pyelliptic.Cipher.get_blocksize('aes-256-cfb'):])
        
        cslo=lzma.decompress(cslobl,format=lzma.FORMAT_ALONE)

        

        return cslo


    def kecsl_encslob(self,data):
        
        cslob=data
        iv=pyelliptic.Cipher.gen_IV('aes-256-cfb')
        
        cslobl=lzma.compress(cslob,format=lzma.FORMAT_ALONE)
        encer=pyelliptic.Cipher(self.Runtimevar['cslskey'],iv,1,ciphername='aes-256-cfb')

        cslobole=encer.ciphering(cslobl)
        csloboleiv=iv+cslobole
        
        return csloboleiv




    def kecsl_recvconn(self,connreqcsl):
        try:

            connreqJSON=self.kecsl_decsl(connreqcsl)
            connreq=json.loads(connreqJSON)
            self.kecsl_checkconnreq(connreq)
            self.kecsl_progressconnreq(connreq)
            connresp=self.kecsl_makerecvconnresp(connreq)
            connrespcsl=self.kecsl_encsl(json.dumps(connresp))
            return connrespcsl
        except Exception:
            pass
        else:
            pass

    def kecsl_isrereceive(self,data):
        thishash=data
        if thishash==self.Runtimevar['lastrecv512']:
            return 1
        else:
            self.Runtimevar['lastrecv512']=thishash
            return 0

        

    def kecsl_recvconnresp(self,connrespcsl):
        try:
            connrespJSON=self.kecsl_decsl(connrespcsl)
            connresp=json.loads(connrespJSON)
            return self.kecsl_progrecvconnresp(connresp)
        except Exception:
            pass
        else:
            pass

    def kecsl_decsl(self,data):
        Conneccobj=pyelliptic.ECC(pubkey=base64.b64decode(self.InstConf['Leccpuk'].encode('utf8')),privkey=base64.b64decode(self.InstConf['Leccpvk'].encode('utf8')),curve='secp521r1')
        cslbl=Conneccobj.decrypt(data)
        cslb=lzma.decompress(cslbl,format=lzma.FORMAT_ALONE)
        csl=cslb.decode('utf8')
        return csl
        

    def kecsl_encsl(self,data):
        Conneccobj=pyelliptic.ECC(pubkey=base64.b64decode(self.InstConf['Leccpuk'].encode('utf8')),privkey=base64.b64decode(self.InstConf['Leccpvk'].encode('utf8')),curve='secp521r1')
        cslb=data.encode('utf8')
        cslbl=lzma.compress(cslb,format=lzma.FORMAT_ALONE)
        if self.InstConf['connmode']=='pst':
            cslble=Conneccobj.encrypt(cslbl,base64.b64decode(self.InstConf['Reccpuk'].encode('utf8')))
        else:
            cslble=Conneccobj.encrypt(cslbl,base64.b64decode(self.Runtimevar['Reccpuk'].encode('utf8')))
        
        return cslble
        

    def kecsl_makeconn(self):
        connreq=self.kecsl_makeconnreq()
        connreqJSON=json.dumps(connreq)
        connreqJSONcsl=self.kecsl_encsl(connreqJSON)
        return connreqJSONcsl

    def kecsl_initeccobj(self):
        if self.InstConf['Leccpuk']=='' or self.InstConf['Leccpvk']=='':
            raise Exception('KECSL key not set')

    def InitRuntime(self):
        self.Runtimevar['uuid']=str(uuid.uuid4())
        self.Runtimevar['Ruuid'] = ""
        self.Runtimevar['lastrecv512']=None
        self.kecsl_initeccobj()
        if self.InstConf['authmode']=='eccpuk' and self.InstConf['connmode']=='pst':
            self.eccpukauth_initkeyeccobj()

    def kecsl_send(self,data):

        datacsl=self.kecsl_encslob(data)
        self.Runtimevar["lastsent"]=datacsl
        return datacsl

    def kecsl_receive(self,data):
        if self.kecsl_isrereceive(data)==0:
            datadecsl=self.kecsl_decslob(data)
            return True,datadecsl

        else:
            return False,None

    def kecsl_resend(self):
            return self.Runtimevar["lastsent"]

    def auth_makeauthresult(self,res):
        retv=''
        if res:
            retv="Succ"
        else:
            retv='Err' 
        authresult={}
        authresult['stat']=retv
        
        return self.kecsl_encsl(json.dumps(authresult))

    def auth_checkauthresult(self,rescsl):
        authresult=json.loads(self.kecsl_decsl(rescsl))
        if authresult['stat']=='Succ':
            return True
        else:
            return False


    def Connect(self):
        if self.InstConf['connmode']=="pst":
            if self.Runtimevar['uuid']!="":
                if not self.Runtimevar['Ruuid']!='':
                    return self.kecsl_makeconn()
                else:
                    raise Exception('Already Connected')
            else:
                raise Exception('Runtime not inited.')
                
        else:
            raise Exception("Mode is not pst, should wait for Connection")

    
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
            challenge=self.eccpukauth_makechallenge()


        if self.Runtimevar['Rauthmode']=='passwd':
            challenge=self.passwdauth_makechallenge()

        challengecsl=self.kecsl_encsl(challenge)
        return challengecsl

    def OnAskForAuth(self,datacsl):
        data=self.kecsl_decsl(datacsl)
        Authd=json.loads(data)
        if self.Runtimevar['Rauthmode']=='eccpuk':
            challenge=self.eccpukauth_finishchallenge(Authd)


        if self.Runtimevar['Rauthmode']=='passwd':
            challenge=self.passwdauth_finishchallenge(Authd)

        challengedcsl=self.kecsl_encsl(challenge)
        return challengedcsl

    def OnReceiveAuth(self,datacsl):
        data=self.kecsl_decsl(datacsl)
        Authd=json.loads(data)
        if self.Runtimevar['Rauthmode']=='eccpuk':
            result=self.eccpukauth_verifychallenge(Authd)


        if self.Runtimevar['Rauthmode']=='passwd':
            result=self.passwdauth_verifychallenge(Authd)

        
        return result,self.auth_makeauthresult(result)

    def OnReceiveAuthReply(self,datacsl):
        return self.auth_checkauthresult(datacsl)

    def GenKECSLkey(self):
        self.kecsl_genkey()

    def Geneccauthkey(self):
        self.eccpukauth_genkey()

    def SetEcckeyCallback(self,func):
        self.Runtimevar['callback_GetEccPukByID']=func

    def SetPasswsCallback(self,func):
        self.Runtimevar['callback_GetPasswdHashByID']=func

    def OnReceiveConnectionReply(self,data):
        return self.kecsl_recvconnresp(data)

        