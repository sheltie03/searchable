# 類似検索暗号の実装
## Charm入門
Charm Dir : `/usr/local/lib/python2.7/site-packages/charm`
### 整数の計算練習

```
$ python
>>> from charm.core.math.integer import integer,isPrime,gcd,random,randomPrime,toInt
>>> p = randomPrime(1024)
>>> q = randomPrime(1024)
>>> type(N)
<type 'integer.Element'>
>>> p * 2 / p == 2
True
>>> p * 2 % p == 0
True
>>> phi_N = (p - 1) * (q - 1)
>>> e = random(phi_N)
>>> d = e ** -1 　← .so(Share Object形式)ファイルで中身が見えない
>>> N = p * q
>>> print gcd(p, q)
1
```

### 余談：soファイルを逆アセンブルする
soファイルはCからPythonへの拡張(Embedding)の際に作られるモジュールである．

```
$ objdump -d /usr/local/lib/python2.7/site-packages/charm/core/math/integer.so > tmp
$ less tmp
(省略) アセンブラが読めれば...
```

### RSA 

```
from charm.core.math.integer import integer,isPrime,gcd,random,randomPrime,toInt
from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.PKSig import PKSig
from charm.toolbox.paddingschemes import OAEPEncryptionPadding,PSSPadding
from charm.toolbox.conversion import Conversion
from math import ceil
```

```
>>> rsa = RSA_Enc()
>>> [public_key, secret_key] = rsa.keygen(1024)
>>> msg = "RSA is not secure."
>>> cipher_text = rsa.encrypt(public_key, msg)
>>> decrypted_msg = rsa.decrypt(public_key, secret_key, cipher_text)
>>> print msg
RSA is not secure.
>>> decrypted_msg == msg
True
```

### ElGamal Encryption

```
from charm.toolbox.PKEnc import PKEnc
from charm.toolbox.ecgroup import G
```


```
>>> from charm.schemes.pkenc.pkenc_elgamal85 import ElGamal
>>> from charm.toolbox.integergroup import IntegerGroupQ, integer, randomPrime
>>> q = randomPrime(1024)
>>> p = 2 * q + 1
>>> groupObj = IntegerGroupQ()
>>> el = ElGamal(groupObj, p, q)
>>> (public_key, secret_key) = el.keygen()
>>> msg = "ElGamal is very old."
>>> cipher_text = el.encrypt(public_key, msg)
>>> decrypted_msg = el.decrypt(public_key, secret_key, cipher_text)    
>>> decrypted_msg == msg
True
```

```
>>> from charm.toolbox.eccurve import prime192v2
>>> from charm.toolbox.ecgroup import ECGroup
>>> groupObj = ECGroup(prime192v2)
>>> el = ElGamal(groupObj)
>>> (public_key, secret_key) = el.keygen()
>>> msg = "ElGamal with elliptic curves is not secure."
>>> cipher_text = el.encrypt(public_key, msg)
>>> decrypted_msg = el.decrypt(public_key, secret_key, cipher_text)
>>> decrypted_msg == msg
True

```

### Paillier Cryptosystem

```
from charm.toolbox.integergroup import lcm,integer
from charm.toolbox.PKEnc import PKEnc
from charm.core.engine.util import *
```


```
>>> from charm.toolbox.integergroup import RSAGroup
>>> from charm.schemes.pkenc.pkenc_paillier99 import Pai99
>>> group = RSAGroup()
>>> pai = Pai99(group)
>>> (public_key, secret_key) = pai.keygen()
>>> msg_1=12345678987654321
>>> msg_2=12345761234123409
>>> msg_3 = msg_1 + msg_2
    
>>> msg_1 = pai.encode(public_key['n'], msg_1)
>>> msg_2 = pai.encode(public_key['n'], msg_2)
>>> msg_3 = pai.encode(public_key['n'], msg_3) 
    
>>> cipher_1 = pai.encrypt(public_key, msg_1)
>>> cipher_2 = pai.encrypt(public_key, msg_2)
>>> cipher_3 = cipher_1 + cipher_2
    
>>> decrypted_msg_3 = pai.decrypt(public_key, secret_key, cipher_3)
>>> decrypted_msg_3 == msg_3
True

```

### Schnorr Signature

```
from charm.toolbox.integergroup import IntegerGroupQ
from charm.toolbox.PKSig import PKSig
```

```
from charm.schemes.pksig.pksig_schnorr91 import SchnorrSig
from charm.core.math.integer import integer, randomPrime
q = randomPrime(1024)
p = 2 * q + 1
pksig = SchnorrSig()
pksig.params(p, q)
(public_key, secret_key) = pksig.keygen()
msg = "Schnorr is stingy."
signature = pksig.sign(public_key, secret_key, msg)
pksig.verify(public_key, signature, msg)
False(うまくいかない?)
```



### DSA

```
from charm.toolbox.integergroup import IntegerGroupQ
from charm.toolbox.PKSig import PKSig
```

```
>>> from charm.schemes.pksig.pksig_dsa import DSA
>>> from charm.core.math.integer import integer, randomPrime
>>> q = randomPrime(1024)
>>> p = 2 * q + 1
>>> dsa = DSA(p, q)
>>> (public_key, secret_key) = dsa.keygen(1024)
>>> msg = "DSA does not spread the world."
>>> signature = dsa.sign(public_key, secret_key, msg)
>>> dsa.verify(public_key, signature, msg)
Falses(うまくいかない？)
```

## ペアリングの実装(Python編)

### Charmで使えるペアリング曲線
+ 宮地らの楕円曲線Miyaji-Nakabayashi-Takano曲線はAsymmetric曲線であり，159ビットと201ビット，224ビットが使用可能である．(MNT159, MNT201, MNT224)
+ SS曲線とはSymmetric曲線であり，Super Singular曲線の略である．(SS512, SS1024)

### IDベース暗号(ペアリング)
詳しくは[Charm: A Framework for Rapidly Prototyping Cryptosystems](https://eprint.iacr.org/2011/617.pdf)を参照．
Charm Dir : `/usr/local/lib/python2.7/site-packages/charm`

+ BF01 : `charm/schemes/ibenc/ibenc_bf01.py` (?)
+ BB03 : `charm/schemes/ibenc/ibenc_bb03.py` (ok)
+ BB04 : `charm/schemes/hibenc/hibenc_bb04.py`
+ Waters05 : `charm/schemes/ibenc/ibenc_waters05.py`(?)
+ SW05 : `charm/schemes/ibenc/ibenc_sw05.py` (ok)
+ BSW07 : `charm/schemes/abenc/abenc_bsw07.py`
+ LSW09 : `charm/schemes/abenc/abenc_lsw08.py`?
+ LSW08 : `charm/schemes/ibencibenc_lsw08.py` (ok)
+ Waters08 : `charm/schemes/ibenc/ibenc_waters09_z.py`
+ LW10 : $\ $  None

### BB03

```
# -*- using: utf-8 -*-

from charm.schemes.ibenc.ibenc_bb03 import IBE_BB04
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,\
GT,pair
from charm.core.crypto.cryptobase import *
from charm.toolbox.IBEnc import *
from charm.core.math.pairing import hashPair as sha1

group = PairingGroup('MNT224')
ibe = IBE_BB04(group)
(master_public_key, master_key) = ibe.setup()
master_public_key_ID = group.random(ZR)
key = ibe.extract(master_key, master_public_key_ID)
msg = group.random(GT)
cipher_text = ibe.encrypt(master_public_key, master_public_ke\
y_ID, msg)
decrypted_msg = ibe.decrypt(master_public_key, key, cipher_te\
xt)
print decrypted_msg == msg
```

```
$ emacs bb03.py
$ python bb03.py
True
```

### SW05

```
# -*- using: utf-8 -*-

from charm.schemes.ibenc.ibenc_sw05 import IBE_SW05_LUC
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.IBEnc import IBEnc
from charm.toolbox.secretshare import SecretShare


from charm.toolbox.pairinggroup import PairingGroup,GT
group = PairingGroup('SS512')
max_attributes = 6
required_overlap = 4
ibe = IBE_SW05_LUC(group)
(master_public_key, master_key) = ibe.setup(max_attributes, required_overlap)
private_identity = ['insurance', 'id=2345', 'oncology', 'doctor', 'nurse', 'JHU'] #private identity
public_identity = ['insurance', 'id=2345', 'doctor', 'oncology', 'JHU', 'billing', 'misc'] #public identity for encrypt
(pub_ID_hashed, secret_key) = ibe.extract(master_key, private_identity, master_public_key, required_overlap, max_attributes)
msg = group.random(GT)
cipher_text = ibe.encrypt(master_public_key, public_identity, msg, max_attributes)
decrypted_msg = ibe.decrypt(master_public_key, secret_key, cipher_text, pub_ID_hashed, required_overlap)
print msg == decrypted_msg
```

```
$ emacs sw05.py
$ python sw05.py
True
```

### LSW08

```
# -*- using: utf-8 -*-                                        
from charm.toolbox.pairinggroup import ZR,G1,pair
from charm.toolbox.IBEnc import *
from charm.schemes.ibenc.ibenc_lsw08 import IBE_Revoke

from charm.toolbox.pairinggroup import PairingGroup, GT, G2
group = PairingGroup('SS512')
num_users = 5 # total # of users                              
ibe = IBE_Revoke(group)
ID = "user2@email.com"
S = ["user1@email.com", "user3@email.com", "user4@email.com"]
(master_public_key, master_secret_key) = ibe.setup(num_users)
secret_key = ibe.keygen(master_public_key, master_secret_key,\
 ID)
msg = group.random(GT)
cipher_text = ibe.encrypt(master_public_key, msg, S)
decrypted_msg = ibe.decrypt(S, cipher_text, secret_key)
print decrypted_msg == msg
```

```
$ emacs lsw08.py
$ python lsw08.py
True
```


# Appendix

## PyCrypto

```
$ pip install pycrypto
$ python
>>> from Crypto.Util.number import *
(これで多倍長が使えるようになる!!)
```

[PyCrypto](https://www.dlitz.net/software/pycrypto/api/current/Crypto-module.html)などを参照すれば，PyCryptoのAPIを見つけることができる．次に[Crypto.Util.number](https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.number-module.html#bytes_to_long)のAPIを掲載する．簡単な暗号ならば，ここのAPIとハッシュ関数hashlibさえあればほとんど実装することができる．

```
size(N) : Nのビット長
GCD(x, y) : x, yの最大公約数
inverse(x, y) : 法yでのxの逆元
getRandomNumber(N, None) : Nビットまでの乱数
getRandomInteger(N, None) : Nビットまでの乱数の整数
getRandomNBitInteger(N, None) : Nビットの乱数の整数
getPrime(N, None) : Nビットの素数
isPrime(N, 1e-06, None) : Nが素数か？(素数:1，非素数:0, 偶数:False)
long_to_bytes(N, n) : nブロックに10進数Nを16進数に変換する
bytes_to_long(N) : 文字列Nを長整数に
```

## Hashlib
現時点で実装されているハッシュ関数はMD5, SHA1(sha1), SHA224(sha224), SHA256(sha256), SHA384(sha384), SHA512(sha512)である．

```
$ python
>>> import hashlib
>>> hashlib.md5().hexdigest()
'd41d8cd98f00b204e9800998ecf8427e'
>>> hashlib.sha1().hexdigest()
'da39a3ee5e6b4b0d3255bfef95601890afd80709'
```

この内，md5は2004年に衝突が見つかり現在では使われていない．また，sha1は2008年に衝突が見つかり2010年に[NIST](http://www.nist.gov/)が運用中止した．現在はsha2(sha256)へシフトしつつある．


## GMP
### インストール前

```
$ sudo apt-get install gcc
$ sudo apt-get install clang
$ sudo aptitude build-dep gcc
```

### インストール


```
$ brew gmp
$ find / -name gmp
usr/local/Cellar/gmp
$ emacs ~/.bash_profile
```

.bash_profileに次を書き足し，`gmp.h`などのincludeを許可する．

```
export CPATH=$CPATH:/usr/local/Cellar/gmp/6.1.0/include
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/Cellar/gmp/6.1.0/lib
```


### コンパイル
コンパイルのときにGNU MP Libraryにリンクさせる必要がある．

```
$ gcc -lgmp test.c
```

## PBC
### インストール前
ubuntuの場合，flexとbisonが無いといわれる可能性がある．

```
$ sudo apt-get install flex
$ sudo apt-get install bison
```

### インストール

```
$ brew pbc
$ find / -name pbc
usr/local/Cellar/pbc
$ emacs ~/.bash_profile
```

.bash_profileに次を書き足し，`pbc.h`などのincludeを許可する．

```
export CPATH=$CPATH:/usr/local/Cellar/pbc/0.5.14/include
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/Cellar/pbc/0.5.14/lib
```

### コンパイル
コンパイルのときにPBC Libraryにリンクさせる必要がある．

```
$ gcc -lpbc test.c
```

### 簡単なペアリングによる署名の実装
test.c

```
#include <stdio.h>
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <gmp.h>
#define BASE 10

int main(int argc, char **argv) {
	pairing_t pairing;
	pbc_demo_pairing_init(pairing, argc, argv);

	element_t g, h;
	element_t pk, sk;
	element_t sign, tmp1, tmp2;

	element_init_G1(g, pairing);
	element_init_G1(pk, pairing);
	element_init_G2(h, pairing);
	element_init_G2(sign, pairing);
	element_init_GT(tmp1, pairing);
	element_init_GT(tmp2, pairing);
	element_init_Zr(sk, pairing);

	element_random(g);
	element_random(sk);
	
	element_pow_zn(pk, g, sk);
	element_from_hash(h, "ABCDEF", 6);
	element_pow_zn(sign, h, sk);

	pairing_apply(tmp1, sign, g, pairing);
	pairing_apply(tmp2, h, pk, pairing);

	if (!element_cmp(tmp1, tmp2)) {
		printf("OK\n");
	}
	
	return 0;
}
```

実行

```
$ gcc -lpbc -lgmp test.c
$ ./a.out a.param
OK
$ ./a.out a1.param
OK
$ ./a.out e.param
OK
```

### C言語での乱数生成

pbc_rnd.c

```
#include <stdio.h>
#include <gmp.h>
#include <pbc/pbc.h>

#define BASE 10

int main(void) {
	unsigned int t = 1024;
	mpz_t a, b;
	mpz_init(a);
	mpz_init(b);
	mpz_set_str(a, "1024", BASE);

	pbc_mpz_random(b, a);
	mpz_out_str(stdout, BASE, b);
	printf("¥n");

	pbc_mpz_randomb(b, t);
	mpz_out_str(stdout, BASE, b);
	printf("¥n");

	return 0;
}
```

```
$ gcc -lpbc -lgmp pbc_rnd.c
$ ./a.out
476 (1024までの乱数)
22557655637352286320129344473752341153476428572018664927422769698148381623800232298669489016992093118648462892380897355841326020670915365403721954328481232897840989170647832912691619439095632055389145851332723260854985980810333271993481962595704616437923270080265877152744438833030689124801952189791038133290 (1024ビットの乱数)

```

## Charm

### Charm-Crypto のインストール
[ドキュメント](http://jhuisi.github.io/charm/)を参照して，インストールを行う．

```
$ pip install charm-crypto
$ python
>>> from charm.toolbox.integergroup import IntegerGroup
dlopen(/usr/local/lib/python2.7/site-packages/charm/core/math/integer.so, 2): Library not loaded: libcrypto.1.0.0.dylib
  Referenced from: /usr/local/lib/python2.7/site-packages/charm/core/math/integer.so
  Reason: image not found
>>> quit()
$ find -n name libcrypto.1.0.0.dylib
/usr/local/Cellar/openssl/1.0.2a-1/lib/libcrypto.1.0.0.dylib
$ ln -s /usr/local/Cellar/openssl/1.0.2e_1/lib/libcrypto.1.0.0.dylib /usr/local/lib/  
```
## Python から C への拡張
### コンパイル
コンパイルのときにPython Static Libraryにリンクさせる必要がある．

```
$ gcc -lpython test.c
```

## C から Python への埋め込み
### Ctypes

```
$ emacs ext.c
#include <stdio.h>
void hello(void) {
	printf("Hello!");
}
$ gcc -Wall -fPIC -c ext.c -I/usr/include/python2.7
$ ls
ext.c ext.o
$ gcc -lpython -shared -o ext.so ext.o
$ ls
ext.c ext.o ext.so
$ python
>>> import ctypes
>>> ext = ctypes.CDLL("./ext.so")
>>> ext.hello()
Hello!!
```

## Cython
Cythonのソースコードは最適化済みのC/C++コードに翻訳されて，Pythonの拡張モジュールとしてコンパイルされる．

### setup.py

```
from distutils.core import setup
from distutils.extension import Extension
from Cython.Distutils import build_ext

ext_modules = [Extension("hello", ["hello.pyx"])]

setup(
  name = 'Hello world app',
  cmdclass = {'build_ext': build_ext},
  ext_modules = ext_modules
)
```

### hello.pyx

```
def say_hello_to(name):
    print("Hello %s!" % name)
```

```
$ python setup.py build_ext --inplace
running build_ext
cythoning hello.pyx to hello.c
building 'hello' extension
creating build
creating build/temp.macosx-10.10-x86_64-2.7
clang -fno-strict-aliasing -fno-common -dynamic -g -O2 -DNDEBUG -g -fwrapv -O3 -Wall -Wstrict-prototypes -I/usr/local/include -I/usr/local/opt/openssl/include -I/usr/local/opt/sqlite/include -I/usr/local/Cellar/python/2.7.10_2/Frameworks/Python.framework/Versions/2.7/include/python2.7 -c hello.c -o build/temp.macosx-10.10-x86_64-2.7/hello.o
hello.c:1613:28: warning: unused function
      '__Pyx_PyObject_AsString' [-Wunused-function]
static CYTHON_INLINE char* __Pyx_PyObject_AsString(...
                           ^
hello.c:1610:32: warning: unused function
      '__Pyx_PyUnicode_FromString' [-Wunused-function]
static CYTHON_INLINE PyObject* __Pyx_PyUnicode_From...
                               ^
hello.c:325:29: warning: unused function
      '__Pyx_Py_UNICODE_strlen' [-Wunused-function]
static CYTHON_INLINE size_t __Pyx_Py_UNICODE_strlen...
                            ^
hello.c:1675:26: warning: unused function
      '__Pyx_PyObject_IsTrue' [-Wunused-function]
static CYTHON_INLINE int __Pyx_PyObject_IsTrue(PyOb...
                         ^
hello.c:1725:33: warning: unused function
      '__Pyx_PyIndex_AsSsize_t' [-Wunused-function]
static CYTHON_INLINE Py_ssize_t __Pyx_PyIndex_AsSsi...
                                ^
hello.c:1787:33: warning: unused function
      '__Pyx_PyInt_FromSize_t' [-Wunused-function]
static CYTHON_INLINE PyObject * __Pyx_PyInt_FromSiz...
                                ^
hello.c:1146:32: warning: unused function
      '__Pyx_PyInt_From_long' [-Wunused-function]
static CYTHON_INLINE PyObject* __Pyx_PyInt_From_lon...
                               ^
hello.c:1197:27: warning: function '__Pyx_PyInt_As_long' is
      not needed and will not be emitted
      [-Wunneeded-internal-declaration]
static CYTHON_INLINE long __Pyx_PyInt_As_long(PyObj...
                          ^
hello.c:1381:26: warning: function '__Pyx_PyInt_As_int' is
      not needed and will not be emitted
      [-Wunneeded-internal-declaration]
static CYTHON_INLINE int __Pyx_PyInt_As_int(PyObject *x) {
                         ^
9 warnings generated.
clang -bundle -undefined dynamic_lookup build/temp.macosx-10.10-x86_64-2.7/hello.o -L/usr/local/lib -L/usr/local/opt/openssl/lib -L/usr/local/opt/sqlite/lib -o /Users/Akihiko/Desktop/hello.so
$ ls
hello.pyx setup.pyのほか：build(ディレクトリ) hello.so hello.c ができている
$ python
>>> from hello import say_hello_to
>>> say_hello_to(1)
Hello 1! (できてる...)
$ emacs hello.c
(cythonはpython2.7の下にあるのでその場所をincludeするように変更する)
$ gcc -lpython hello.c
Undefined symbols for architecture x86_64:
  "_main", referenced from:
     implicit entry/start for main executable
     (maybe you meant: ___pyx_module_is_main_test)
ld: symbol(s) not found for architecture x86_64
clang: error: linker command failed with exit code 1 (use -v to see invocation)
(main関数がない...?)
$ emacs test.c (main関数を書く)
$ gcc -lpython test.c
$ ./a.out
```

## OpenSSL
### インストール


```
$ brew openssl
$ find / -name openssl
usr/local/Cellar/openssl
$ emacs ~/.bash_profile
```

.bash_profileに次を書き足し，`sha.h`などのincludeを許可する．

```
export CPATH=$CPATH:/usr/local/Cellar/openssl/1.0.2a-1/include
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/Cellar/openssl/1.0.2a-1/lib
export CPATH=$CPATH:/usr/local/Cellar/openssl/1.0.2d_1/include
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/Cellar/openssl/1.0.2d_1/lib
```


### コンパイル
コンパイルのときにOpenSSL Libraryにリンクさせる必要がある．

```
$ gcc -lssl test.c
$ gcc -lcrypto test.c
```

## Charmの比較：Paillier暗号
### 実行環境
CPUがIntel Core i5 1.3 GHz，メモリが8 GB，OSがMac OS X El Capitan 10.11.2である．

### 比較の概要
+ CharmのPai99クラスのメソッド・・・(a)
+ PyCryptoを用いたPythonでの単純実装・・・(b)
+ GMPを用いたC言語での単純実装・・・(c)
+ BigIntegerを用いたJavaでの単純実装・・・(d)

### 計測の概要
2つの512ビット素数を用いて25ビットの定平文(19910813)を暗号化する操作(1)，そして復号する操作(2)の各時間[msec]，または(3)合計時間[msec]を比較する．

### 計算の結果

||Encryption|Decryption|Enc + Dec|
|:--:|:--:|:--:|:--:|
|(a)|91.50 $\pm$ 7.07|87.31 $\pm$ 5.63|172.06 $\pm$ 11.24|
|(b)|20.32 $\pm$ 1.48|39.29 $\pm$ 1.54|60.02 $\pm$ 2.40|
|(c)|10.72|16.86|26.24|
|(d)|14.38 $\pm$ 2.52|27.44 $\pm$ 3.37|39.26 $\pm$ 4.27|



### 比較の結果
C < Java < Python < Charm