#!/usr/bin/env python

import time
from loki_bindings import bf

def run_test(obj):
    t0 = time.time()
    obj.start()
    while obj.running:
        time.sleep(0.01)
        #~ try: print obj.cur_pw 
        #~ except: pass
    t1 = time.time()
    print "password: '%s' in ~%.2fs" % (obj.pw, t1-t0)

print "*** OSPF - MD5 ***"
obj = bf.ospf_md5_bf()
obj.pre_data = "0201002cac10000a00000000000000020000011054f4c94affffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "c9d952c775f955edf3b81e952f8f410f".decode("hex")
run_test(obj)

print "*** OSPF - HMAC-SHA1 ***"
obj = bf.ospf_hmac_sha1_bf()
obj.pre_data = "0201002cac10000a00000000000000020000011454ee45b9ffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "53169aee3185a2ec8c26adce8b3677669b10da1c".decode("hex")
run_test(obj)

print "*** OSPF - HMAC-SHA256 ***"
obj = bf.ospf_hmac_sha256_bf()
obj.pre_data = "0201002cac10000a00000000000000020000012054f4c8adffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "508a1abffb5b4554e1aa46eb053bca7105c3e8f6fece4c945f0a0020edb054ec".decode("hex")
run_test(obj)

print "*** OSPF - HMAC-SHA384 ***"
obj = bf.ospf_hmac_sha384_bf()
obj.pre_data = "0201002cac10000a00000000000000020000013054f4c8e4ffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "9dcf336773034f4ad8b0e19c52546ba72fd91d79d9416c9c1c4854002d3c0b5fc7c80fc1c4994ab9b6c48d9c6ac03587".decode("hex")
run_test(obj)

print "*** OSPF - HMAC-SHA512 ***"
obj = bf.ospf_hmac_sha512_bf()
obj.pre_data = "0201002cac10000a00000000000000020000014054f4c912ffffff00000a120100000028c0a86f0a00000000".decode("hex")
obj.hash_data = "4faa125881137ab3257ee9c8626d0ffa0c387c2e41a832d435afffc41d35881360fbe74442191a8aef201a4aad2689577a0c26a3cc5c681e72f09c297d16ba6a".decode("hex")
run_test(obj)

print "*** ISIS - HMAC-MD5 ***"
obj = bf.isis_hmac_md5_bf()
obj.pre_data = "831401001101000301192168201101001b005a000104034900018102cc8ee50400000002e810fe800000000000000465fffffe000000f00f0000000004192168201104000000040a113600000000000000000000000000000000".decode("hex")
obj.hash_data = "44b62860b363f9adf60acdb9d66abe27".decode("hex")
run_test(obj)

print "*** ISIS - HMAC-SHA1 ***"
obj = bf.isis_hmac_sha1_bf()
obj.pre_data = "831401001101000301192168201101001b004e000104034900018102cc8e8404c0a8ca00f00f0000000003192168201104000000030a17030001".decode("hex")
obj.hash_data = "0a33e7acf138d0bfb2b197f331bbd8ae237e0465".decode("hex")
run_test(obj)

print "*** ISIS - HMAC-SHA256 ***"
obj = bf.isis_hmac_sha256_bf()
obj.pre_data = "831401001101000301192168201101001b005a000104034900018102cc8e8404c0a8ca00f00f0000000003192168201104000000030a23030002".decode("hex")
obj.hash_data = "3082271800f8fab2976d57bb5d1d6e182189b9a2d542f48371da934f854acab9".decode("hex")
run_test(obj)

print "*** BFD - MD5 ***"
obj = bf.bfd_md5_bf()
obj.pre_data = "20c4053000001001000010010000c3500000c350000000000218010000000004".decode("hex")
obj.hash_data = "6b9c6391428a7175476436c7ccfb7338".decode("hex")
run_test(obj)

print "*** BFD - SHA1 ***"
obj = bf.bfd_sha1_bf()
obj.pre_data = "20c4053400001001000010010000c3500000c35000000000041c01000000047f".decode("hex")
obj.hash_data = "46f075e931f5dbc0914c981dc074e60c56cef919".decode("hex")
run_test(obj)

print "*** TCPMD5 ***"
obj = bf.tcpmd5_bf()
obj.pre_data = "45c000401c8340000106fd05c0a86f0ac0a86f14d05d00b32ff1bc6400000000b0024000c6360000020405b41312ed37a465e55a8155ac1c953ce087f7c30000".decode("hex")
obj.hash_data = "ed37a465e55a8155ac1c953ce087f7c3".decode("hex")
run_test(obj)

print "*** TACACS+ ***"
obj = bf.tacacs_bf()
obj.pre_data = "6d0e1631".decode("hex")
obj.hash_data = "c006".decode("hex")
obj.ciphertext = "db7c01e77499".decode("hex")
run_test(obj)




