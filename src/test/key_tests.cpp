// Copyright (c) 2012-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "key.h"

#include "base58.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"
#include "utilstrencodings.h"
#include "random.h"
#include "test/test_bitcoin.h"

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

using namespace std;

static const string strSecret1     ("5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj");
static const string strSecret2     ("5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3");
static const string strSecret1C    ("Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw");
static const string strSecret2C    ("L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g");
static const CBitcoinAddress addr1 ("1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ");
static const CBitcoinAddress addr2 ("1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ");
static const CBitcoinAddress addr1C("1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs");
static const CBitcoinAddress addr2C("1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs");


static const string strAddressBad("1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF");


#ifdef KEY_TESTS_DUMPINFO
void dumpKeyInfo(uint256 privkey)
{
    CKey key;
    key.resize(32);
    memcpy(&secret[0], &privkey, 32);
    vector<unsigned char> sec;
    sec.resize(32);
    memcpy(&sec[0], &secret[0], 32);
    printf("  * secret (hex): %s\n", HexStr(sec).c_str());

    for (int nCompressed=0; nCompressed<2; nCompressed++)
    {
        bool fCompressed = nCompressed == 1;
        printf("  * %s:\n", fCompressed ? "compressed" : "uncompressed");
        CBitcoinSecret bsecret;
        bsecret.SetSecret(secret, fCompressed);
        printf("    * secret (base58): %s\n", bsecret.ToString().c_str());
        CKey key;
        key.SetSecret(secret, fCompressed);
        vector<unsigned char> vchPubKey = key.GetPubKey();
        printf("    * pubkey (hex): %s\n", HexStr(vchPubKey).c_str());
        printf("    * address (base58): %s\n", CBitcoinAddress(vchPubKey).ToString().c_str());
    }
}
#endif


BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CBitcoinSecret bsecret1, bsecret2, bsecret1C, bsecret2C, baddress1;
    BOOST_CHECK( bsecret1.SetString (strSecret1));
    BOOST_CHECK( bsecret2.SetString (strSecret2));
    BOOST_CHECK( bsecret1C.SetString(strSecret1C));
    BOOST_CHECK( bsecret2C.SetString(strSecret2C));
    BOOST_CHECK(!baddress1.SetString(strAddressBad));

    CKey key1  = bsecret1.GetKey();
    BOOST_CHECK(key1.IsCompressed() == false);
    CKey key2  = bsecret2.GetKey();
    BOOST_CHECK(key2.IsCompressed() == false);
    CKey key1C = bsecret1C.GetKey();
    BOOST_CHECK(key1C.IsCompressed() == true);
    CKey key2C = bsecret2C.GetKey();
    BOOST_CHECK(key2C.IsCompressed() == true);

    CPubKey pubkey1  = key1. GetPubKey();
    CPubKey pubkey2  = key2. GetPubKey();
    CPubKey pubkey1C = key1C.GetPubKey();
    CPubKey pubkey2C = key2C.GetPubKey();

    std::cout << "pub1:  " << pubkey1 .IsCompressed() << ", " << pubkey1 .size() << ", " << HexStr(pubkey1 ) << std::endl;
    std::cout << "pub2:  " << pubkey2 .IsCompressed() << ", " << pubkey2 .size() << ", " << HexStr(pubkey2 ) << std::endl;
    std::cout << "pub1c: " << pubkey1C.IsCompressed() << ", " << pubkey1C.size() << ", " << HexStr(pubkey1C) << std::endl;
    std::cout << "pub2c: " << pubkey2C.IsCompressed() << ", " << pubkey2C.size() << ", " << HexStr(pubkey2C) << std::endl;

    BOOST_CHECK(key1.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key1C.VerifyPubKey(pubkey1));
    BOOST_CHECK(key1C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key1C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey1C));
    BOOST_CHECK(key2.VerifyPubKey(pubkey2));
    BOOST_CHECK(!key2.VerifyPubKey(pubkey2C));

    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey1C));
    BOOST_CHECK(!key2C.VerifyPubKey(pubkey2));
    BOOST_CHECK(key2C.VerifyPubKey(pubkey2C));

    BOOST_CHECK(addr1.Get()  == CTxDestination(pubkey1.GetID()));
    BOOST_CHECK(addr2.Get()  == CTxDestination(pubkey2.GetID()));
    BOOST_CHECK(addr1C.Get() == CTxDestination(pubkey1C.GetID()));
    BOOST_CHECK(addr2C.Get() == CTxDestination(pubkey2C.GetID()));

    {
      vector<unsigned char> id(16), s1(64), s2(128), s3(256);
#if 0
      for (unsigned i = 0; i < s1.size(); i += 32) GetStrongRandBytes(&s1[i], 32);
      for (unsigned i = 0; i < s2.size(); i += 32) GetStrongRandBytes(&s2[i], 32);
      for (unsigned i = 0; i < s3.size(); i += 32) GetStrongRandBytes(&s3[i], 32);
      std::cout << "s1: " << HexStr(s1) << std::endl;
      std::cout << "s2: " << HexStr(s2) << std::endl;
      std::cout << "s3: " << HexStr(s3) << std::endl;
#else
      s1 = ParseHex("328e83c8ab18f6af2a88e155453346e850427296bda487c65f448cc7613f11e811b330d9cb9bbe1bc576e9f87a58cacc1ea44d88ba512a25216ed565f00b1b16");
      s2 = ParseHex("8eca65c6f404d6d92a9664cd77e4ce88d558b395df13d4698063a598b5d6f063946723d63228914bcb2f01db4aabbd269a5731cc6cfedce705552ea5f41ee774224f4d117c071253308f53b082926b3c6185d668fb28d74559ce2bf38372f103c380386fba145979902d3a897a6d32e35983a75f47b10b0318fa4c901d3dae59");
      s3 = ParseHex("88c7fbcb591a1359ab9958844b0bf328c63b02d4c23df9a2efe8746ee7cc96a8bf34b769ab25809985bfc65b985f8129d7a562063cd29bdc0886aab5cc40fd34ba43c9085dcfdede444f2a507087990a4cf02f8e75769feae48458728cc7b87a9928c94468c8475a0c0286d98e32d90ca0aba5901b4ce1ac9baa140606b009577dc09d9cc0b2687f361297f6a41c4346187e9e4dcd5bae5a5523f3038a9195ab1e66d210b9b598c202da9c0b321dfc75a10476021501213fcf9fc60529ed585cf44f0f49b85f45b058a82229a2ae0b94d5b2dfe2461d31cd39303d943acccef37772fa40a9b8dd91f58dbb9da90ce8c9177c28d180ca9a6d6978b17f76945653");
#endif
      for (int n = 0; n < 50; ++n) {
        GetStrongRandBytes(&id[0], id.size());
        
        uint256 h;
        std::vector<unsigned char> vch(id);
        h = Hash(vch.begin(), vch.end());
        vch.assign(h.begin(), h.end());
        vch.insert(vch.begin(), id.begin(), id.end());
        vch.insert(vch.end(), s1.begin(), s1.end());
        h = Hash(vch.begin(), vch.end());
        vch.assign(h.begin(), h.end());
        vch.insert(vch.end(), s2.begin(), s2.end());
        h = Hash(vch.begin(), vch.end());
        vch.assign(h.begin(), h.end());
        vch.insert(vch.end(), s3.begin(), s3.end());
        h = Hash(vch.begin(), vch.end());
        vch.assign(h.begin(), h.end());

        //std::cout << n << ": " << HexStr(id) << ", " << HexStr(vch) << std::endl;

        for (int i = 0; i < 16; ++i) vch[i] ^= vch[i + 16];
        vch.resize(16);
        
        std::cout << n << ": " << HexStr(id) << ", " << HexStr(vch) << std::endl;
      }
    }
    {
      vector<unsigned char> msg;
      string strMsg1("VEChain Test Message");
      string strMsg2("VEChain Test Salt");
      uint256 h1 = Hash(strMsg1.begin(), strMsg1.end());
      msg.insert(msg.end(), h1.begin(), h1.end());
      msg.insert(msg.end(), strMsg2.begin(), strMsg2.end());

      uint256 hashMsg = Hash(msg.begin(), msg.end());
      vector<unsigned char> sign1, sign2, sign1c, sign2c;
      BOOST_CHECK(key1.Sign(hashMsg, sign1));
      BOOST_CHECK(key2.Sign(hashMsg, sign2));
      BOOST_CHECK(key1.SignCompact(hashMsg, sign1c));
      BOOST_CHECK(key2.SignCompact(hashMsg, sign2c));

      // 3044022079714b58a2eae82b1ef729b0d9753f457df2bbc38bb7d57445189f5ede9172fa02201cb8f81e6fcf45bcb6bdf32348c81b0b729e0d14ec43953a4e44a58669a2a2c6
      // 30450221008a1efb3b7e86d3709b0a49e6eb36791bebb4af268d98bc79922789b6eae759a0022041f240522d5fe9365f616f6334269af6de37e0123323d29d2b305e515b372e2c
      
      std::cout << "hash: " << HexStr(hashMsg) << std::endl;
      std::cout << "sig1: " << HexStr(sign1) << ", " << sign1.size() << std::endl;
      std::cout << "sig2: " << HexStr(sign2) << ", " << sign2.size() << std::endl;
      std::cout << "sig1c:" << HexStr(sign1c) << ", " << sign1c.size() << std::endl;
      std::cout << "sig2c:" << HexStr(sign2c) << ", " << sign2c.size() << std::endl;
      std::cout << "-----" << std::endl;

      CPubKey rk1, rk2;
      BOOST_CHECK(rk1.RecoverCompact(hashMsg, sign1c));
      BOOST_CHECK(rk2.RecoverCompact(hashMsg, sign2c));
      std::cout << "pub1:  " << rk1.IsCompressed() << ", " << rk1.size() << ", " << HexStr(rk1) << std::endl;
      std::cout << "pub2:  " << rk2.IsCompressed() << ", " << rk2.size() << ", " << HexStr(rk2) << std::endl;
      std::cout << "----------" << std::endl;
    }

    for (int n=0; n<16; n++)
    {
        string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

        // normal signatures

        vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        std::cout << "hash: " << n << ", " << HexStr(hashMsg) << std::endl;
        std::cout << "sig1: " << HexStr(sign1) << std::endl;
        std::cout << "sig2: " << HexStr(sign2) << std::endl;

        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2.Verify(hashMsg, sign2C));

        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2));
        BOOST_CHECK( pubkey1C.Verify(hashMsg, sign1C));
        BOOST_CHECK(!pubkey1C.Verify(hashMsg, sign2C));

        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2));
        BOOST_CHECK(!pubkey2C.Verify(hashMsg, sign1C));
        BOOST_CHECK( pubkey2C.Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CPubKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.RecoverCompact (hashMsg, csign1));
        BOOST_CHECK(rkey2.RecoverCompact (hashMsg, csign2));
        BOOST_CHECK(rkey1C.RecoverCompact(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.RecoverCompact(hashMsg, csign2C));

        BOOST_CHECK(rkey1  == pubkey1);
        BOOST_CHECK(rkey2  == pubkey2);
        BOOST_CHECK(rkey1C == pubkey1C);
        BOOST_CHECK(rkey2C == pubkey2C);
    }

    // test deterministic signing

    std::vector<unsigned char> detsig, detsigc;
    string strMsg = "Very deterministic message";
    uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());
    BOOST_CHECK(key1.Sign(hashMsg, detsig));
    BOOST_CHECK(key1C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("304402205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d022014ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
    BOOST_CHECK(key2.Sign(hashMsg, detsig));
    BOOST_CHECK(key2C.Sign(hashMsg, detsigc));
    BOOST_CHECK(detsig == detsigc);
    BOOST_CHECK(detsig == ParseHex("3044022052d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd5022061d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
    BOOST_CHECK(key1.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key1C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1c5dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d14ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
    BOOST_CHECK(detsigc == ParseHex("205dbbddda71772d95ce91cd2d14b592cfbc1dd0aabd6a394b6c2d377bbe59d31d14ddda21494a4e221f0824f0b8b924c43fa43c0ad57dccdaa11f81a6bd4582f6"));
    BOOST_CHECK(key2.SignCompact(hashMsg, detsig));
    BOOST_CHECK(key2C.SignCompact(hashMsg, detsigc));
    BOOST_CHECK(detsig == ParseHex("1c52d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd561d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
    BOOST_CHECK(detsigc == ParseHex("2052d8a32079c11e79db95af63bb9600c5b04f21a9ca33dc129c2bfa8ac9dc1cd561d8ae5e0f6c1a16bde3719c64c2fd70e404b6428ab9a69566962e8771b5944d"));
}

BOOST_AUTO_TEST_SUITE_END()
