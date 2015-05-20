// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

//#include "chainparamsseeds.h"

unsigned int pnSeed[] =
{
    0x026422c3,
	0xa4bd5bd4,
	0x46ed9c5e,
};


int64_t CChainParams::GetProofOfWorkReward(int nHeight, int64_t nFees) const
{
    int64_t nSubsidy = 0 * COIN;
 
    if(pindexBest->nHeight+1 == 1)
    {
        nSubsidy = 1000000 * COIN; // ICO
    }
	    else if(pindexBest->nHeight+1 >= 2 && pindexBest->nHeight+1 <= 300)
    {
        nSubsidy = 0 * COIN;
    }
        else if(pindexBest->nHeight+1 >= 301 && pindexBest->nHeight+1 <= 1440)
    {
        nSubsidy = 50 * COIN;
    }
        else if(pindexBest->nHeight+1 >= 1441 && pindexBest->nHeight+1 <= 2880)
    {
        nSubsidy = 25 * COIN;
    }
        else if(pindexBest->nHeight+1 >= 2881 && pindexBest->nHeight+1 <= 4321)
    {
        nSubsidy = 10 * COIN;
    }
    
    if (fDebug && GetBoolArg("-printcreation"))
        LogPrintf("GetProofOfWorkReward() : create=%s nSubsidy=%d\n", FormatMoney(nSubsidy).c_str(), nSubsidy);
    
    return nSubsidy + nFees;
};


int64_t CChainParams::GetProofOfStakeReward(int64_t nCoinAge, int64_t nFees) const
{

   // proof of stake rewards. POS begins at block 2500

    int64_t nSubsidy = nCoinAge * COIN_YEAR_REWARD * 33 / (365 * 33 + 8); //default 10% yr
	
        if(pindexBest->nHeight+1 >= 2500 && pindexBest->nHeight+1 <= 3500)
    {
        nSubsidy = 3 * COIN;
    }
        else if(pindexBest->nHeight+1 >= 3501 && pindexBest->nHeight+1 <= 4500)
    {
        nSubsidy = 5 * COIN;
    }
        else if(pindexBest->nHeight+1 >= 4501 && pindexBest->nHeight+1 <= 5500)
    {
        nSubsidy = 7 * COIN;
    }
        else if(pindexBest->nHeight+1 >= 5501 && pindexBest->nHeight+1 <= 7500)
    {
        nSubsidy = 10 * COIN;
    }
        else if(pindexBest->nHeight+1 >= 7501 && pindexBest->nHeight+1 <= 8500)
    {
        nSubsidy = 50 * COIN;
    }
        else if(pindexBest->nHeight+1 >= 8501 && pindexBest->nHeight+1 <= 9000)
    {
        nSubsidy = 10 * COIN;
    }
		else if(pindexBest->nHeight+1 > 9001)
    {
        nSubsidy = nCoinAge * COIN_YEAR_REWARD * 33 / (365 * 33 + 8);  //default 10% yr
    }    
    


    
    if (fDebug && GetBoolArg("-printcreation"))
        LogPrintf("GetProofOfStakeReward(): create=%s nCoinAge=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge);
    
    return nSubsidy + nFees;
}

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

// Convert the pnSeeds6 array into usable address objects.
static void convertSeeds(std::vector<CAddress> &vSeedsOut, unsigned int *data, unsigned int count, int port)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in_addr ip;
        memcpy(&ip, &pnSeed[i], sizeof(ip));
        CAddress addr(CService(ip, Params().GetDefaultPort()));
        addr.nTime = GetTime()-GetRand(nOneWeek)-nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0x2c;
        pchMessageStart[2] = 0x77;
        pchMessageStart[3] = 0x11;
        
        vAlertPubKey = ParseHex("04fbc83783aa8c1000ec91e6942ab2a4a9004ab994a752ee02bec2286d33abf2a69ed1e021012aa194fe87a93c2f30bedb39d5067bb025df8bcd17519183940349");
        
        nDefaultPort = 28374;
        nRPCPort = 28375;
        
        nMoreStakePosBlock = 4320;
		nStartPosBlock = 2500;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20); // "standard" scrypt target limit for proof of work, results with 0,000244140625 proof-of-work difficulty
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 48);
        
        const char* pszTimestamp = "StealthCash 2015 Currency";
        CTransaction txNew;
        txNew.nTime = GENESIS_BLOCK_TIME;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 0 << CBigNum(42) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = GENESIS_BLOCK_TIME;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 778635;

        hashGenesisBlock = genesis.GetHash();	
        assert(hashGenesisBlock == uint256("0x00000cd75e7abbba1a7a8c033b35f53e5a440a070306f7b784bdc19ab17cdc39"));
       assert(genesis.hashMerkleRoot == uint256("0xf9ec0c2754d927d15074f58c22c8a37170b054a22a8e0f7aaa5ba1ee43324be6"));
			
        vSeeds.push_back(CDNSSeedData("195.34.100.2", "195.34.100.2"));
		vSeeds.push_back(CDNSSeedData("212.91.189.164", "212.91.189.164"));
		vSeeds.push_back(CDNSSeedData("94.156.237.70", "94.156.237.70"));
        
        base58Prefixes[PUBKEY_ADDRESS] = list_of(63);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(85);
        base58Prefixes[SECRET_KEY]     = list_of(150);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0xEE)(0x80)(0x41)(0x1B);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0xEE)(0x80)(0x23)(0xC2);
        
        //convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));
        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);

        nLastPOWBlock = 4321;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const std::vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    std::vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;

//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0x22;
        pchMessageStart[2] = 0x1b;
        pchMessageStart[3] = 0xc2;
        
        
        nMoreStakePosBlock = 4320;
        
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        bnProofOfStakeLimit = CBigNum(~uint256(0) >> 16);
        
        vAlertPubKey = ParseHex("04a56aa283a1cbb1c3e5ce92ecd531f80459c0143522fc8006f5a86c68263f5f446b92813c7624299e9b19a19de230eaaa02a51f21fe55b4d10ff1d578468c6ce0");
        nDefaultPort = 31997;
        nRPCPort = 31996;
        strDataDir = "testnet";

        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 25498;
        hashGenesisBlock = genesis.GetHash();

        assert(hashGenesisBlock == uint256("0x00008dccee37e63aed57cf71b0ec51b29571191590ef17f46b8258d24d875cce"));

		
        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = list_of(15);
        base58Prefixes[SCRIPT_ADDRESS] = list_of(126);
        base58Prefixes[SECRET_KEY]     = list_of(205);
        base58Prefixes[EXT_PUBLIC_KEY] = list_of(0x76)(0xC0)(0xFD)(0xFB);
        base58Prefixes[EXT_SECRET_KEY] = list_of(0x76)(0xC1)(0x07)(0x7A);
        
        //convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));
        convertSeeds(vFixedSeeds, pnSeed, ARRAYLEN(pnSeed), nDefaultPort);

        //nLastPOWBlock = 0x7fffffff;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        pchMessageStart[0] = 0xff;
        pchMessageStart[1] = 0xcc;
        pchMessageStart[2] = 0x22;
        pchMessageStart[3] = 0xd1;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1401111111;
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 1;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 28444;
        strDataDir = "regtest";

        assert(hashGenesisBlock == uint256("0x032c4675d5454306a29d73b11299340ac4ba5005a1bca47c61719c3dee7a55c1"));
		 vSeeds.clear();
	}
    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

const CChainParams &TestNetParams() {
    return testNetParams;
}

const CChainParams &MainNetParams() {
    return mainParams;
}

void SelectParams(CChainParams::Network network)
{
    switch (network)
    {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    };
};

bool SelectParamsFromCommandLine()
{
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest)
    {
        return false;
    };

    if (fRegTest)
    {
        SelectParams(CChainParams::REGTEST);
    } else
    if (fTestNet)
    {
        SelectParams(CChainParams::TESTNET);
    } else
    {
        SelectParams(CChainParams::MAIN);
    };
    
    return true;
}
