// Copyright (c) 2013-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Unit tests for alert system

#include "alert.h"
#include "chain.h"
#include "chainparams.h"
#include "clientversion.h"
#include "data/alertTests.raw.h"
#include "main.h" // For PartitionCheck
#include "serialize.h"
#include "streams.h"
#include "util.h"
#include "utilstrencodings.h"

#include "test/test_bitcoin.h"

#include <fstream>

#include <boost/filesystem/operations.hpp>
#include <boost/foreach.hpp>
#include <boost/test/unit_test.hpp>

#if 0
//
// alertTests contains 7 alerts, generated with this code:
// (SignAndSave code not shown, alert signing key is secret)
//
{
    CAlert alert;
    alert.nRelayUntil   = 60;
    alert.nExpiration   = 24 * 60 * 60;
    alert.nID           = 1;
    alert.nCancel       = 0;   // cancels previous messages up to this ID number
    alert.nMinVer       = 0;  // These versions are protocol versions
    alert.nMaxVer       = 999001;
    alert.nPriority     = 1;
    alert.strComment    = "Alert comment";
    alert.strStatusBar  = "Alert 1";

    SignAndSave(alert, "test/alertTests");

    alert.setSubVer.insert(std::string("/Satoshi:0.1.0/"));
    alert.strStatusBar  = "Alert 1 for Satoshi 0.1.0";
    SignAndSave(alert, "test/alertTests");

    alert.setSubVer.insert(std::string("/Satoshi:0.2.0/"));
    alert.strStatusBar  = "Alert 1 for Satoshi 0.1.0, 0.2.0";
    SignAndSave(alert, "test/alertTests");

    alert.setSubVer.clear();
    ++alert.nID;
    alert.nCancel = 1;
    alert.nPriority = 100;
    alert.strStatusBar  = "Alert 2, cancels 1";
    SignAndSave(alert, "test/alertTests");

    alert.nExpiration += 60;
    ++alert.nID;
    SignAndSave(alert, "test/alertTests");

    ++alert.nID;
    alert.nMinVer = 11;
    alert.nMaxVer = 22;
    SignAndSave(alert, "test/alertTests");

    ++alert.nID;
    alert.strStatusBar  = "Alert 2 for Satoshi 0.1.0";
    alert.setSubVer.insert(std::string("/Satoshi:0.1.0/"));
    SignAndSave(alert, "test/alertTests");

    ++alert.nID;
    alert.nMinVer = 0;
    alert.nMaxVer = 999999;
    alert.strStatusBar  = "Evil Alert'; /bin/ls; echo '";
    alert.setSubVer.clear();
    SignAndSave(alert, "test/alertTests");
}
#endif

struct ReadAlerts : public TestingSetup
{
    ReadAlerts()
    {
        std::vector<unsigned char> vch(alert_tests::alertTests, alert_tests::alertTests + sizeof(alert_tests::alertTests));
        CDataStream stream(vch, SER_DISK, CLIENT_VERSION);
        try {
            while (!stream.eof())
            {
                CAlert alert;
                stream >> alert;
                alerts.push_back(alert);
            }
        }
        catch (const std::exception&) { }
    }
    ~ReadAlerts() { }

    static std::vector<std::string> read_lines(boost::filesystem::path filepath)
    {
        std::vector<std::string> result;

        std::ifstream f(filepath.string().c_str());
        std::string line;
        while (std::getline(f,line))
            result.push_back(line);

        return result;
    }

    std::vector<CAlert> alerts;
};

BOOST_FIXTURE_TEST_SUITE(Alert_tests, ReadAlerts)


static bool falseFunc() { return false; }

BOOST_AUTO_TEST_CASE(PartitionAlert)
{
    // Test PartitionCheck
    CCriticalSection csDummy;
    CBlockIndex indexDummy[100];
    CChainParams& params = Params(CBaseChainParams::MAIN);
    int64_t nPowTargetSpacing = params.GetConsensus().nPowTargetSpacing;

    // Generate fake blockchain timestamps relative to
    // an arbitrary time:
    int64_t now = 1427379054;
    SetMockTime(now);
    for (int i = 0; i < 100; i++)
    {
        indexDummy[i].phashBlock = NULL;
        if (i == 0) indexDummy[i].pprev = NULL;
        else indexDummy[i].pprev = &indexDummy[i-1];
        indexDummy[i].nHeight = i;
        indexDummy[i].nTime = now - (100-i)*nPowTargetSpacing;
        // Other members don't matter, the partition check code doesn't
        // use them
    }

    strMiscWarning = "";

    // Test 1: chain with blocks every nPowTargetSpacing seconds,
    // as normal, no worries:
    PartitionCheck(falseFunc, csDummy, &indexDummy[99], nPowTargetSpacing);
    BOOST_CHECK_MESSAGE(strMiscWarning.empty(), strMiscWarning);

    // Test 2: go 3.5 hours without a block, expect a warning:
    now += 3*60*60+30*60;
    SetMockTime(now);
    PartitionCheck(falseFunc, csDummy, &indexDummy[99], nPowTargetSpacing);
    BOOST_CHECK(!strMiscWarning.empty());
    BOOST_TEST_MESSAGE(std::string("Got alert text: ")+strMiscWarning);
    strMiscWarning = "";

    // Test 3: test the "partition alerts only go off once per day"
    // code:
    now += 60*10;
    SetMockTime(now);
    PartitionCheck(falseFunc, csDummy, &indexDummy[99], nPowTargetSpacing);
    BOOST_CHECK(strMiscWarning.empty());

    // Test 4: get 2.5 times as many blocks as expected:
    now += 60*60*24; // Pretend it is a day later
    SetMockTime(now);
    int64_t quickSpacing = nPowTargetSpacing*2/5;
    for (int i = 0; i < 100; i++) // Tweak chain timestamps:
        indexDummy[i].nTime = now - (100-i)*quickSpacing;
    PartitionCheck(falseFunc, csDummy, &indexDummy[99], nPowTargetSpacing);
    //BOOST_CHECK(!strMiscWarning.empty());
    //BOOST_TEST_MESSAGE(std::string("Got alert text: ")+strMiscWarning);
    strMiscWarning = "";

    SetMockTime(0);
}

BOOST_AUTO_TEST_SUITE_END()
