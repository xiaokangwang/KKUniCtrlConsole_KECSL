#!/usr/bin/env python3
import base64
import nose
import KECSLInst
import pyelliptic
import lzma
from hashlib import sha512
#import pudb; pu.db



def test_KECSLInst_class_Instancify():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    assert(theKECSLInst is not None)

def test_KECSLInst_class_Initconfig_server():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.InitConfig('ltn')

def test_KECSLInst_class_Initconfig_connector_passwdauth():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.InitConfig('pst','passwd')

def test_KECSLInst_class_Initconfig_connector_eccpukauth():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.InitConfig('pst','eccpuk')

def test_KECSLInst_class_Initconfig_connector_wrong_mod():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    try:
        theKECSLInst.InitConfig('wrong_test')
    except Exception as err:
        assert(str(err)=="Unknown connmode.")
    else:
        assert(False)

def test_KECSLInst_class_Initconfig_connector_wrong_auth():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    try:
        theKECSLInst.InitConfig('pst','wrong_test')
    except Exception as err:
        assert(str(err)=="Unknown authmode.")
    else:
        assert(False)

def test_KECSLInst_class_Exportconfig_initpasswd():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.InitConfig('pst','passwd')
    assert(theKECSLInst.ExportConfig()=={'Leccpuk': '', 'connmode': 'pst', 'Reccpuk': '', 'Leccpvk': '', 'authmode': 'passwd'})

def test_KECSLInst_class_Exportconfig_initeccpuk():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.InitConfig('pst','eccpuk')
    assert(theKECSLInst.ExportConfig()=={'authmode': 'eccpuk', 'Leccpvk': '', 'connmode': 'pst', 'Reccpuk': '', 'Leccpuk': ''})

def test_KECSLInst_class_Setconfig():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.InitConfig('pst','eccpuk')
    theKECSLInst.SetConfig('test_testconfig','test_testconfig_val')
    assert(theKECSLInst.ExportConfig()=={'authmode': 'eccpuk', 'Leccpvk': '', 'connmode': 'pst', 'Reccpuk': '', 'Leccpuk': '','test_testconfig':'test_testconfig_val'})

def test_KECSLInst_class_KECSL_MakeEccKey():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.InitConfig('ltn')
    theKECSLInst.GenKECSLkey()
    config=theKECSLInst.ExportConfig()
    assert(config['Leccpvk']!='')
    assert(config['Leccpuk']!='')

def test_KECSLInst_class_eccauth_MakeEccKey():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.InitConfig('pst','eccpuk')
    theKECSLInst.Geneccauthkey()
    config=theKECSLInst.ExportConfig()
    assert(config['Autheccpuk']!='')
    assert(config['Autheccpvk']!='')

def test_KECSLInst_class_Loadconfig():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    theKECSLInst.LoadConfig({'authmode': 'eccpuk', 'Leccpvk': '', 'connmode': 'pst', 'Reccpuk': '', 'Leccpuk': '','test_testconfig':'test_testconfig_val','test_testconfig2':'test_testconfig_val2'})
    assert(theKECSLInst.ExportConfig()=={'authmode': 'eccpuk', 'Leccpvk': '', 'connmode': 'pst', 'Reccpuk': '', 'Leccpuk': '','test_testconfig':'test_testconfig_val','test_testconfig2':'test_testconfig_val2'})

def test_KECSLInst_class_ltninitruntime():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInst.InitRuntime()

def test_KECSLInst_class_pst_initruntime_passwd_auth():
    theKECSLInst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInst.GenKECSLkey()
    theKECSLInst.InitRuntime()

def test_KECSLInst_class_initbothltnpst():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

def test_KECSLInst_class_makeconnectreq():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

def test_eccencdecutl():
    eccltn=pyelliptic.ECC(pubkey=base64.b64decode('AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='.encode('utf8')),privkey=base64.b64decode('AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ=='.encode('utf8')),curve='secp521r1')
    eccpst=pyelliptic.ECC(curve='secp521r1')
    enced=eccpst.encrypt(b'encrypt_demo',base64.b64decode('AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='.encode('utf8')))
    data=eccltn.decrypt(enced)
    assert(data ==b'encrypt_demo')

def test_lzmautl():
    lzmat=b'demo-lzma'
    lzmatl=lzma.compress(lzmat,format=lzma.FORMAT_ALONE)
    lzmatlu=lzma.decompress(lzmatl,format=lzma.FORMAT_ALONE)
    assert(lzmatlu==lzmat)

def test_KECSLInst_class_asencey_varopera():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()
    a=pyelliptic.ECC(pubkey=base64.b64decode(theKECSLInstltn.ExportConfig()['Leccpuk'].encode('utf8')),privkey=base64.b64decode(theKECSLInstltn.ExportConfig()['Leccpvk'].encode('utf8')),curve='secp521r1')
    b=pyelliptic.ECC(curve='secp521r1')

    encde=b.encrypt(b'encrypt_demovar',base64.b64decode(theKECSLInstPst.InstConf['Reccpuk'].encode('utf8')))
    decdata=a.decrypt(encde)

    assert(decdata ==b'encrypt_demovar')



def test_KECSLInst_class_asencey():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    encde=theKECSLInstPst.kecsl_encsl('test_KECSLInst_class_asencey')
    decdata=theKECSLInstltn.kecsl_decsl(encde)

    assert(decdata =='test_KECSLInst_class_asencey')


def test_KECSLInst_class_submitconnectreq():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

def test_KECSLInst_class_progress_connreqsign():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

def test_KECSLInst_class_progress_senddata():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

    datatosend=b'test_KECSLInst_class_progress_senddata'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)

def test_KECSLInst_class_progress_senddataandreply():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

    datatosend=b'test_KECSLInst_class_progress_senddataandreply(prv)'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)


    datatoreply=b'test_KECSLInst_class_progress_senddataandreply(rep)'

    replyenc=theKECSLInstltn.Send(datatoreply)

    progressneed,replydata=theKECSLInstPst.OnReceive(replyenc)

    assert(progressneed)

    assert(replydata==datatoreply)

def test_KECSLInst_class_progress_senddatadoubleandreply():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

    datatosend=b'test_KECSLInst_class_progress_senddataandreply(prv)'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)

    datatosend=b'test_KECSLInst_class_progress_senddataandreply(prv2)'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)


    datatoreply=b'test_KECSLInst_class_progress_senddataandreply(rep)'

    replyenc=theKECSLInstltn.Send(datatoreply)

    progressneed,replydata=theKECSLInstPst.OnReceive(replyenc)

    assert(progressneed)

    assert(replydata==datatoreply)


def test_KECSLInst_class_progress_senddataAndResendandreply():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

    datatosend=b'test_KECSLInst_class_progress_senddataandreply(prv)'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)

    encdata2=theKECSLInstPst.Resend()

    assert(encdata is not None)

    assert(encdata2==encdata)

    progressneed,discard=theKECSLInstltn.OnReceive(encdata2)


    assert(not progressneed)


    datatoreply=b'test_KECSLInst_class_progress_senddataandreply(rep)'

    replyenc=theKECSLInstltn.Send(datatoreply)

    progressneed,replydata=theKECSLInstPst.OnReceive(replyenc)

    assert(progressneed)

    assert(replydata==datatoreply)


def test_hashlib():
    assert(sha512('passwddemo'.encode('utf8')).hexdigest()=='f3c13cfdd4567d86c7356cf546831ed48ed967a0ef1e95993760c91405d974b129d852b7a7e3192376844f9d7bdbe731717d45602ff80acfa775064b0249db46')

def test_KECSLInst_class_progress_senddataAndResendandreply_andauth1():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

    datatosend=b'test_KECSLInst_class_progress_senddataandreply(prv)'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)

    encdata2=theKECSLInstPst.Resend()

    assert(encdata is not None)

    assert(encdata2==encdata)

    progressneed,discard=theKECSLInstltn.OnReceive(encdata2)


    assert(not progressneed)


    datatoreply=b'test_KECSLInst_class_progress_senddataandreply(rep)'

    replyenc=theKECSLInstltn.Send(datatoreply)

    progressneed,replydata=theKECSLInstPst.OnReceive(replyenc)

    assert(progressneed)

    assert(replydata==datatoreply)


    theKECSLInstltn.SetPasswsCallback(lambda x:sha512('passwddemo'.encode('utf8')).hexdigest())

    challdata=theKECSLInstltn.AskforAuth()

    assert(challdata is not None)



def test_KECSLInst_class_progress_senddataAndResendandreply_andauth2():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

    datatosend=b'test_KECSLInst_class_progress_senddataandreply(prv)'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)

    encdata2=theKECSLInstPst.Resend()

    assert(encdata is not None)

    assert(encdata2==encdata)

    progressneed,discard=theKECSLInstltn.OnReceive(encdata2)


    assert(not progressneed)


    datatoreply=b'test_KECSLInst_class_progress_senddataandreply(rep)'

    replyenc=theKECSLInstltn.Send(datatoreply)

    progressneed,replydata=theKECSLInstPst.OnReceive(replyenc)

    assert(progressneed)

    assert(replydata==datatoreply)


    theKECSLInstltn.SetPasswsCallback(lambda x:sha512('passwddemo'.encode('utf8')).hexdigest())

    challdata=theKECSLInstltn.AskforAuth()

    assert(challdata is not None)

    theKECSLInstPst.SetConfig('authas',"tester")

    theKECSLInstPst.SetConfig('passwdhash',"f3c13cfdd4567d86c7356cf546831ed48ed967a0ef1e95993760c91405d974b129d852b7a7e3192376844f9d7bdbe731717d45602ff80acfa775064b0249db46")

    challdatarep=theKECSLInstPst.OnAskForAuth(challdata)

    assert(challdatarep is not None)



def test_KECSLInst_class_progress_senddataAndResendandreply_andauth3():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

    datatosend=b'test_KECSLInst_class_progress_senddataandreply(prv)'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)

    encdata2=theKECSLInstPst.Resend()

    assert(encdata is not None)

    assert(encdata2==encdata)

    progressneed,discard=theKECSLInstltn.OnReceive(encdata2)


    assert(not progressneed)


    datatoreply=b'test_KECSLInst_class_progress_senddataandreply(rep)'

    replyenc=theKECSLInstltn.Send(datatoreply)

    progressneed,replydata=theKECSLInstPst.OnReceive(replyenc)

    assert(progressneed)

    assert(replydata==datatoreply)


    theKECSLInstltn.SetPasswsCallback(lambda x:sha512('passwddemo'.encode('utf8')).hexdigest())

    challdata=theKECSLInstltn.AskforAuth()

    assert(challdata is not None)

    theKECSLInstPst.SetConfig('authas',"tester")

    theKECSLInstPst.SetConfig('passwdhash',"f3c13cfdd4567d86c7356cf546831ed48ed967a0ef1e95993760c91405d974b129d852b7a7e3192376844f9d7bdbe731717d45602ff80acfa775064b0249db46")

    challdatarep=theKECSLInstPst.OnAskForAuth(challdata)

    assert(challdatarep is not None)


    authto,replyauth=theKECSLInstltn.OnReceiveAuth(challdatarep)

    assert(authto=="tester")

    assert(replyauth is not None)

    authresult=theKECSLInstPst.OnReceiveAuthReply(replyauth)
    assert(authresult)






def test_KECSLInst_class_progress_eccauth():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'eccpuk', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=','Autheccpvk': 'AswAQgFIvbSfTDY8vi7ynRYJedAHQFKnHmTj7wce+LGBgUwU7MQlVrPwyyAaWgIZ0b0eSLlsn/P1vN51ckzmSHjL2d3dsQ==','Autheccpuk': 'AswAQgGBpfKSe7dBwPaqckWp8ey0wJnLgp+EjiOPFsFKWjIyV8HsADWKGpcLCqNE3ZrYGY0bIifEJI1l9O3u92qfXmQGFQBCARRRw+q8otHvr1xMAFWb3Wno1tw836K0wczrkBGnPqF2URrUJKkl9uuCDDbOiP2rVWDqqJqwTYnNDzbSO708AytF'})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)


    theKECSLInstltn.SetEcckeyCallback(lambda x:'AswAQgGBpfKSe7dBwPaqckWp8ey0wJnLgp+EjiOPFsFKWjIyV8HsADWKGpcLCqNE3ZrYGY0bIifEJI1l9O3u92qfXmQGFQBCARRRw+q8otHvr1xMAFWb3Wno1tw836K0wczrkBGnPqF2URrUJKkl9uuCDDbOiP2rVWDqqJqwTYnNDzbSO708AytF')

    theKECSLInstPst.SetConfig('authas',"tester")

    challdata=theKECSLInstltn.AskforAuth()


    challdatarep=theKECSLInstPst.OnAskForAuth(challdata)

    assert(challdatarep is not None)


    authto,replyauth=theKECSLInstltn.OnReceiveAuth(challdatarep)



    assert(authto=="tester")

    assert(replyauth is not None)


    authresult=theKECSLInstPst.OnReceiveAuthReply(replyauth)
    assert(authresult)




def test_KECSLInst_class_progress_eccauth_shouldfail():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'eccpuk', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=','Autheccpvk': 'AswAQgFIvbSfTDY8vi7ynRYJedAHQFKnHmTj7wce+LGBgUwU7MQlVrPwyyAaWgIZ0b0eSLlsn/P1vN51ckzmSHjL2d3dsQ==','Autheccpuk': 'AswAQgGBpfKSe7dBwPaqckWp8ey0wJnLgp+EjiOPFsFKWjIyV8HsADWKGpcLCqNE3ZrYGY0bIifEJI1l9O3u92qfXmQGFQBCARRRw+q8otHvr1xMAFWb3Wno1tw836K0wczrkBGnPqF2URrUJKkl9uuCDDbOiP2rVWDqqJqwTYnNDzbSO708AytF'})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)


    theKECSLInstltn.SetEcckeyCallback(lambda x:'AswAQgEufrXfLJHu3OG6k6IgHWmkcQSgVM20kKPuQPtddZ7AYJWj7F/YaAffFlLZDe2wXoDvKz0XjRD8XKUeqZES96+clABCASy8YaGRy9jN/79YF30Ms1SZBV1Db4NEZtS/BmzXjk92KsHKg4dLy6yd5zgrPx+/F5Y42qFprY8aHEFCprIDURKq')

    theKECSLInstPst.SetConfig('authas',"tester")

    challdata=theKECSLInstltn.AskforAuth()


    challdatarep=theKECSLInstPst.OnAskForAuth(challdata)

    assert(challdatarep is not None)


    authto,replyauth=theKECSLInstltn.OnReceiveAuth(challdatarep)



    assert(authto == None)

    assert(replyauth is not None)


    authresult=theKECSLInstPst.OnReceiveAuthReply(replyauth)
    assert(not authresult)




def test_KECSLInst_class_progress_senddataAndResendandreply_andauth3_shouldfail():
    theKECSLInstltn=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstltn.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q=', 'connmode': 'ltn', 'Leccpvk': 'AswAQgG5NbwMh7P/Wi1m6ZwzPJ3ewYJT9T0jciFDRDKxKqG4jfi7podAUhZjx7tg5heaq2fC0/fhOCFJ13ZHPKq+BWvuDQ==', 'authmode': 'eccpuk', 'Reccpuk': ''})
    theKECSLInstltn.InitRuntime()

    theKECSLInstPst=KECSLInst.KKUniCtrlConsole_KECSLInst()
    #this key for test purpose only
    theKECSLInstPst.LoadConfig({'test_testconfig': 'test_testconfig_val', 'Leccpvk': '','Leccpuk': '', 'connmode': 'pst', 'authmode': 'passwd', 'Reccpuk': 'AswAQVkgk55c6FMiA7ufhREI20LgGIkoecVtebmRrQLks7rNCL9QIzV84iY+L0GUf0UrAa7koAbOjSI+kVSYcX4oPb4AAEIB7Di87TRbXXt+Ef32eSQwovsgecQyJxZMzvHRfqLz5vWe8T9czdgpSZIhjQ688MlqIXPMELASGHUl31TuThqmr6Q='})
    theKECSLInstPst.GenKECSLkey()
    theKECSLInstPst.InitRuntime()

    conndata=theKECSLInstPst.Connect()

    assert(conndata is not None)

    connrespdata=theKECSLInstltn.OnRecvConnectReq(conndata)

    assert(connrespdata is not None)

    result=theKECSLInstPst.OnReceiveConnectionReply(connrespdata)

    assert(result)

    datatosend=b'test_KECSLInst_class_progress_senddataandreply(prv)'

    encdata=theKECSLInstPst.Send(datatosend)

    assert(encdata is not None)

    progressneed,deencdata=theKECSLInstltn.OnReceive(encdata)

    assert(progressneed)

    assert(deencdata==datatosend)

    encdata2=theKECSLInstPst.Resend()

    assert(encdata is not None)

    assert(encdata2==encdata)

    progressneed,discard=theKECSLInstltn.OnReceive(encdata2)


    assert(not progressneed)


    datatoreply=b'test_KECSLInst_class_progress_senddataandreply(rep)'

    replyenc=theKECSLInstltn.Send(datatoreply)

    progressneed,replydata=theKECSLInstPst.OnReceive(replyenc)

    assert(progressneed)

    assert(replydata==datatoreply)


    theKECSLInstltn.SetPasswsCallback(lambda x:sha512('the correct password is not passwddemo'.encode('utf8')).hexdigest())

    challdata=theKECSLInstltn.AskforAuth()

    assert(challdata is not None)

    theKECSLInstPst.SetConfig('authas',"tester")

    theKECSLInstPst.SetConfig('passwdhash',"f3c13cfdd4567d86c7356cf546831ed48ed967a0ef1e95993760c91405d974b129d852b7a7e3192376844f9d7bdbe731717d45602ff80acfa775064b0249db46")

    challdatarep=theKECSLInstPst.OnAskForAuth(challdata)

    assert(challdatarep is not None)


    authto,replyauth=theKECSLInstltn.OnReceiveAuth(challdatarep)

    assert(authto==False)

    assert(replyauth is not None)

    authresult=theKECSLInstPst.OnReceiveAuthReply(replyauth)
    assert(not authresult)












if __name__ == '__main__':
    nose.main()