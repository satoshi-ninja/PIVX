// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2016 The DarkNet developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "rpcserver.h"
#include "init.h"
#include "main.h"
#include "script/script.h"
#include "script/standard.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include "wallet.h"
#include "utilstrencodings.h"

#include <fstream>
#include <stdint.h>
#include <secp256k1.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <openssl/sha.h>
#include <openssl/aes.h>

#include "json/json_spirit_value.h"

using namespace json_spirit;
using namespace std;

void EnsureWalletIsUnlocked();

std::string static EncodeDumpTime(int64_t nTime) {
    return DateTimeStrFormat("%Y-%m-%dT%H:%M:%SZ", nTime);
}

int64_t static DecodeDumpTime(const std::string &str) {
    static const boost::posix_time::ptime epoch = boost::posix_time::from_time_t(0);
    static const std::locale loc(std::locale::classic(),
        new boost::posix_time::time_input_facet("%Y-%m-%dT%H:%M:%SZ"));
    std::istringstream iss(str);
    iss.imbue(loc);
    boost::posix_time::ptime ptime(boost::date_time::not_a_date_time);
    iss >> ptime;
    if (ptime.is_not_a_date_time())
        return 0;
    return (ptime - epoch).total_seconds();
}

std::string static EncodeDumpString(const std::string &str) {
    std::stringstream ret;
    BOOST_FOREACH(unsigned char c, str) {
        if (c <= 32 || c >= 128 || c == '%') {
            ret << '%' << HexStr(&c, &c + 1);
        } else {
            ret << c;
        }
    }
    return ret.str();
}

std::string DecodeDumpString(const std::string &str) {
    std::stringstream ret;
    for (unsigned int pos = 0; pos < str.length(); pos++) {
        unsigned char c = str[pos];
        if (c == '%' && pos+2 < str.length()) {
            c = (((str[pos+1]>>6)*9+((str[pos+1]-'0')&15)) << 4) |
                ((str[pos+2]>>6)*9+((str[pos+2]-'0')&15));
            pos += 2;
        }
        ret << c;
    }
    return ret.str();
}

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importprivkey \"darknetprivkey\" ( \"label\" rescan )\n"
            "\nAdds a private key (as returned by dumpprivkey) to your wallet.\n"
            "\nArguments:\n"
            "1. \"darknetprivkey\"   (string, required) The private key (see dumpprivkey)\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nDump a private key\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"") +
            "\nImport the private key with rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\"") +
            "\nImport using a label and without rescan\n"
            + HelpExampleCli("importprivkey", "\"mykey\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importprivkey", "\"mykey\", \"testing\", false")
        );

    EnsureWalletIsUnlocked();

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key encoding");

    CKey key = vchSecret.GetKey();
    if (!key.IsValid()) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CPubKey pubkey = key.GetPubKey();
    assert(key.VerifyPubKey(pubkey));
    CKeyID vchAddress = pubkey.GetID();
    {
        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBook(vchAddress, strLabel, "receive");

        // Don't throw error in case a key is already there
        if (pwalletMain->HaveKey(vchAddress))
            return Value::null;

        pwalletMain->mapKeyMetadata[vchAddress].nCreateTime = 1;

        if (!pwalletMain->AddKeyPubKey(key, pubkey))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");

        // whenever a key is imported, we need to scan the whole chain
        pwalletMain->nTimeFirstKey = 1; // 0 would be considered 'no value'

        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
        }
    }

    return Value::null;
}

Value importaddress(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importaddress \"address\" ( \"label\" rescan )\n"
            "\nAdds an address or script (in hex) that can be watched as if it were in your wallet but cannot be used to spend.\n"
            "\nArguments:\n"
            "1. \"address\"          (string, required) The address\n"
            "2. \"label\"            (string, optional, default=\"\") An optional label\n"
            "3. rescan               (boolean, optional, default=true) Rescan the wallet for transactions\n"
            "\nNote: This call can take minutes to complete if rescan is true.\n"
            "\nExamples:\n"
            "\nImport an address with rescan\n"
            + HelpExampleCli("importaddress", "\"myaddress\"") +
            "\nImport using a label without rescan\n"
            + HelpExampleCli("importaddress", "\"myaddress\" \"testing\" false") +
            "\nAs a JSON-RPC call\n"
            + HelpExampleRpc("importaddress", "\"myaddress\", \"testing\", false")
        );

    CScript script;

    CBitcoinAddress address(params[0].get_str());
    if (address.IsValid()) {
        script = GetScriptForDestination(address.Get());
    } else if (IsHex(params[0].get_str())) {
        std::vector<unsigned char> data(ParseHex(params[0].get_str()));
        script = CScript(data.begin(), data.end());
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DarkNet address or script");
    }

    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    {
        if (::IsMine(*pwalletMain, script) == ISMINE_SPENDABLE)
            throw JSONRPCError(RPC_WALLET_ERROR, "The wallet already contains the private key for this address or script");

        // add to address book or update label
        if (address.IsValid())
            pwalletMain->SetAddressBook(address.Get(), strLabel, "receive");

        // Don't throw error in case an address is already there
        if (pwalletMain->HaveWatchOnly(script))
            return Value::null;

        pwalletMain->MarkDirty();

        if (!pwalletMain->AddWatchOnly(script))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding address to wallet");

        if (fRescan)
        {
            pwalletMain->ScanForWalletTransactions(chainActive.Genesis(), true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return Value::null;
}

Value importwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "importwallet \"filename\"\n"
            "\nImports keys from a wallet dump file (see dumpwallet).\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The wallet file\n"
            "\nExamples:\n"
            "\nDump the wallet\n"
            + HelpExampleCli("dumpwallet", "\"test\"") +
            "\nImport the wallet\n"
            + HelpExampleCli("importwallet", "\"test\"") +
            "\nImport using the json rpc call\n"
            + HelpExampleRpc("importwallet", "\"test\"")
        );

    EnsureWalletIsUnlocked();

    ifstream file;
    file.open(params[0].get_str().c_str(), std::ios::in | std::ios::ate);
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    int64_t nTimeBegin = chainActive.Tip()->GetBlockTime();

    bool fGood = true;

    int64_t nFilesize = std::max((int64_t)1, (int64_t)file.tellg());
    file.seekg(0, file.beg);

    pwalletMain->ShowProgress(_("Importing..."), 0); // show progress dialog in GUI
    while (file.good()) {
        pwalletMain->ShowProgress("", std::max(1, std::min(99, (int)(((double)file.tellg() / (double)nFilesize) * 100))));
        std::string line;
        std::getline(file, line);
        if (line.empty() || line[0] == '#')
            continue;

        std::vector<std::string> vstr;
        boost::split(vstr, line, boost::is_any_of(" "));
        if (vstr.size() < 2)
            continue;
        CBitcoinSecret vchSecret;
        if (!vchSecret.SetString(vstr[0]))
            continue;
        CKey key = vchSecret.GetKey();
        CPubKey pubkey = key.GetPubKey();
        assert(key.VerifyPubKey(pubkey));
        CKeyID keyid = pubkey.GetID();
        if (pwalletMain->HaveKey(keyid)) {
            LogPrintf("Skipping import of %s (key already present)\n", CBitcoinAddress(keyid).ToString());
            continue;
        }
        int64_t nTime = DecodeDumpTime(vstr[1]);
        std::string strLabel;
        bool fLabel = true;
        for (unsigned int nStr = 2; nStr < vstr.size(); nStr++) {
            if (boost::algorithm::starts_with(vstr[nStr], "#"))
                break;
            if (vstr[nStr] == "change=1")
                fLabel = false;
            if (vstr[nStr] == "reserve=1")
                fLabel = false;
            if (boost::algorithm::starts_with(vstr[nStr], "label=")) {
                strLabel = DecodeDumpString(vstr[nStr].substr(6));
                fLabel = true;
            }
        }
        LogPrintf("Importing %s...\n", CBitcoinAddress(keyid).ToString());
        if (!pwalletMain->AddKeyPubKey(key, pubkey)) {
            fGood = false;
            continue;
        }
        pwalletMain->mapKeyMetadata[keyid].nCreateTime = nTime;
        if (fLabel)
            pwalletMain->SetAddressBook(keyid, strLabel, "receive");
        nTimeBegin = std::min(nTimeBegin, nTime);
    }
    file.close();
    pwalletMain->ShowProgress("", 100); // hide progress dialog in GUI

    CBlockIndex *pindex = chainActive.Tip();
    while (pindex && pindex->pprev && pindex->GetBlockTime() > nTimeBegin - 7200)
        pindex = pindex->pprev;

    if (!pwalletMain->nTimeFirstKey || nTimeBegin < pwalletMain->nTimeFirstKey)
        pwalletMain->nTimeFirstKey = nTimeBegin;

    LogPrintf("Rescanning last %i blocks\n", chainActive.Height() - pindex->nHeight + 1);
    pwalletMain->ScanForWalletTransactions(pindex);
    pwalletMain->MarkDirty();

    if (!fGood)
        throw JSONRPCError(RPC_WALLET_ERROR, "Error adding some keys to wallet");

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey \"darknetaddress\"\n"
            "\nReveals the private key corresponding to 'darknetaddress'.\n"
            "Then the importprivkey can be used with this output\n"
            "\nArguments:\n"
            "1. \"darknetaddress\"   (string, required) The darknet address for the private key\n"
            "\nResult:\n"
            "\"key\"                (string) The private key\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpprivkey", "\"myaddress\"")
            + HelpExampleCli("importprivkey", "\"mykey\"")
            + HelpExampleRpc("dumpprivkey", "\"myaddress\"")
        );

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DarkNet address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret).ToString();
}


Value dumpwallet(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpwallet \"filename\"\n"
            "\nDumps all wallet keys in a human-readable format.\n"
            "\nArguments:\n"
            "1. \"filename\"    (string, required) The filename\n"
            "\nExamples:\n"
            + HelpExampleCli("dumpwallet", "\"test\"")
            + HelpExampleRpc("dumpwallet", "\"test\"")
        );

    EnsureWalletIsUnlocked();

    ofstream file;
    file.open(params[0].get_str().c_str());
    if (!file.is_open())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Cannot open wallet dump file");

    std::map<CKeyID, int64_t> mapKeyBirth;
    std::set<CKeyID> setKeyPool;
    pwalletMain->GetKeyBirthTimes(mapKeyBirth);
    pwalletMain->GetAllReserveKeys(setKeyPool);

    // sort time/key pairs
    std::vector<std::pair<int64_t, CKeyID> > vKeyBirth;
    for (std::map<CKeyID, int64_t>::const_iterator it = mapKeyBirth.begin(); it != mapKeyBirth.end(); it++) {
        vKeyBirth.push_back(std::make_pair(it->second, it->first));
    }
    mapKeyBirth.clear();
    std::sort(vKeyBirth.begin(), vKeyBirth.end());

    // produce output
    file << strprintf("# Wallet dump created by DarkNet %s (%s)\n", CLIENT_BUILD, CLIENT_DATE);
    file << strprintf("# * Created on %s\n", EncodeDumpTime(GetTime()));
    file << strprintf("# * Best block at time of backup was %i (%s),\n", chainActive.Height(), chainActive.Tip()->GetBlockHash().ToString());
    file << strprintf("#   mined on %s\n", EncodeDumpTime(chainActive.Tip()->GetBlockTime()));
    file << "\n";
    for (std::vector<std::pair<int64_t, CKeyID> >::const_iterator it = vKeyBirth.begin(); it != vKeyBirth.end(); it++) {
        const CKeyID &keyid = it->second;
        std::string strTime = EncodeDumpTime(it->first);
        std::string strAddr = CBitcoinAddress(keyid).ToString();
        CKey key;
        if (pwalletMain->GetKey(keyid, key)) {
            if (pwalletMain->mapAddressBook.count(keyid)) {
                file << strprintf("%s %s label=%s # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, EncodeDumpString(pwalletMain->mapAddressBook[keyid].name), strAddr);
            } else if (setKeyPool.count(keyid)) {
                file << strprintf("%s %s reserve=1 # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, strAddr);
            } else {
                file << strprintf("%s %s change=1 # addr=%s\n", CBitcoinSecret(key).ToString(), strTime, strAddr);
            }
        }
    }
    file << "\n";
    file << "# End of dump\n";
    file.close();
    return Value::null;
}

Value bip38encrypt(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "bip38encrypt \"darknetaddress\"\n"
            "\nEncrypts a private key corresponding to 'darknetaddress'.\n"
            "\nArguments:\n"
            "1. \"darknetaddress\"   (string, required) The darknet address for the private key\n"
            "2. \"passphrase\"   (string, required) The passphrase you want the private key to be encrypted with\n"
            "\nResult:\n"
            "\"key\"                (string) The encrypted private key\n"
            "\nExamples:\n"
        );

    EnsureWalletIsUnlocked();

    string strAddress = params[0].get_str();
    string strPassword = params[1].get_str();

    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid DarkNet address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CKey vchSecret;
    if (!pwalletMain->GetKey(keyID, vchSecret))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");

    return "done";
}

std::string AddressToBIP38AddressHash(/**CBitcoinAddress address**/string strAddress)
{
    //double SHA256 hash the address
    std::string strHash = Hash(strAddress);
    strHash = Hash(strHash);

    //return the first 4 bytes (2 hex each)
    return strHash.substr(0, 8);
}

Value bip38decrypt(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "bip38decrypt \"darknetaddress\"\n"
            "\nDecrypts a password protected private key.\n"
            "\nArguments:\n"
            "1. \"encryptedkey\"   (string, required) The encrypted private key\n"
            "2. \"passphrase\"   (string, required) The passphrase you want the private key to be encrypted with\n"
            "\nResult:\n"
            "\"key\"                (string) The decrypted private key\n"
            "\nExamples:\n"
        );

    EnsureWalletIsUnlocked();

    /** Collect private key and passphrase **/
    string strPassphrase = params[0].get_str();
    string strKey = DecodeBase58(params[1].get_str().c_str());

    /** 39 bytes - 78 characters
     * 1) Prefix - 2 bytes - 4 chars - strKey[0..3]
     * 2) Flagbyte - 1 byte - 2 chars - strKey[4..5]
     * 3) addresshash - 4 bytes - 8 chars - strKey[6..13]
     * 4) Owner Entropy - 8 bytes - 16 chars - strKey[14..29]
     * 5) Encrypted Part 1 - 8 bytes - 16 chars - strKey[30..45]
     * 6) Encrypted Part 2 - 16 bytes - 32 chars - strKey[46..77]
     */
    // password: TestingOneTwoThree
    // key: 6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX
    // prefix 0143 | flag 00 | addhash 62B5 B722 | owner ent A50D BA67 72CB 9383 | encp1 31A7 C4EC 3B84 DEBA | encp2 1749 E6BE 9706 CF33 4FED 7DF5 65C0 C9FB | b58checksum A454 B0C6

    /** Derive passfactor using scrypt with ownersalt and the user's passphrase and use it to recompute passpoint **/
    //salt is 8 bytes from the key
    string ownersalt = strKey.substr(14, 16);
    string ret = "passphrase: " + HexStr(strPassphrase) + "\nownersalt: " + HexStr(ownersalt);

    //passfactor is the scrypt hash of passphrase and ownersalt (NOTE this needs to handle alt cases too in the future)
    uint256 passfactor;
    char* output = BEGIN(passfactor);
    scrypt_hash(strPassphrase, ownersalt, output, 16384, 8, 8, 32);
    // passFactor: c8ff7a1c8c8898a0361e477fa8f0f05c00d07c5d9626f00b03c0140a307c98f4
    ret += "\n passfactor: " + HexStr(passfactor);

    //passpoint is the ec_mult of passfactor on secp256k1 - this should be the equivalent of just creating a pubkey from it
    CPubKey passpoint;
    int clen = 65;
    secp256k1_ec_pubkey_create((unsigned char*)BEGIN(passpoint), &clen, passfactor.begin(), true);
    //passPoint: 020eac136e97ce6bf3e2bceb65d906742f7317b6518c54c64353c43dcc36688c47
    ret += "\n passPoint: " + HexStr(passpoint);

    /** Derive decryption key for seedb using scrypt with passpoint, addresshash, and ownerentropy **/
    uint512 seedbPass;
    string addressHash = ownersalt;
    scrypt_hash(HexStr(passpoint), addressHash + ownersalt, BEGIN(seedbPass), 1024, 1, 1, 64);
    //seedBPass: da2d320e2ca088575369601e94dd71f210fc69c047a3d0f48bdbaab595916dc7b8d083ea2678b5a71558c0fb0efa58b565227d05adf0c25fa0b9a74755477827
    ret += "\n seedBPass: " +seedbPass.ToStringReverseEndian();

    //get derived halfs, being mindful for endian switch
    uint256 derivedHalf1(seedbPass.ToString().substr(64, 128));
    unsigned char* dh1 = derivedHalf1.begin();
    uint256 d2(seedbPass.ToString().substr(0, 64));
    unsigned char* derivedhalf2 = d2.begin();

    /** Decrypt encryptedpart2 using AES256Decrypt to yield the last 8 bytes of seedb and the last 8 bytes of encryptedpart1. **/
    uint256 dp2;
    char* decryptedPart2 = BEGIN(dp2);
    const char* encryptedPart2 = strKey.substr(62, 93).c_str();

    //decrypted part 2: (encryptedpart1[8..15]+seedb[16..23]) xor derivedhalf1[16..31]
    AES_KEY key;
    AES_set_decrypt_key(derivedhalf2, 256, &key);
    AES_decrypt((unsigned char*)encryptedPart2, (unsigned char*)decryptedPart2, &key);
    //decryptedPart2: 1bca32ddebfc27d15cea84d4005b77ab

    //xor decryptedPart2 and derivedhalf1 - derived half one shift left 64 bits to drop off 0-15
    uint256 x1 = dp2^(derivedHalf1<<64);

    //seedbPart2 is the last half of x1 (64 bytes total)
    uint256 seedbPart2 = x1<<32;
    //seedBPart2: d7312e6195ca1a6c

    /** Decrypt encryptedpart1 to yield the remainder of seedb. **/
    uint256 decryptedPart1;
    char* dp1 = BEGIN(decryptedPart1);
    const char* encryptedPart1 = strKey.substr(30, 61).c_str();

    //decrypted part 1: seedb[0..15] xor derivedhalf1[0..15]
    AES_decrypt((unsigned char*)encryptedPart1, (unsigned char*)dp1, &key);
    uint256 seedbPart1 = decryptedPart1 ^ (derivedHalf1 & uint256("0xffffffffffffffff000000000000000000000000000000000000000000000000"));
    //seedBPart1: 99241d58245c883896f80843d2846672

    //string ret = derivedHalf1.ToString() + "|" + (derivedHalf1 & uint256("0xffffffffffffffff000000000000000000000000000000000000000000000000")).ToString();

    return ret;
}


