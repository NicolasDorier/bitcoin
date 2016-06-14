// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockencodings.h"
#include "consensus/merkle.h"
#include "chainparams.h"
#include "random.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>

struct RegtestingSetup : public TestingSetup {
    RegtestingSetup() : TestingSetup(CBaseChainParams::REGTEST) {}
};

BOOST_FIXTURE_TEST_SUITE(blockencodings_tests, RegtestingSetup)

static CBlock BuildBlockTestCase() {
    CBlock block;
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig.resize(10);
    tx.vout.resize(1);
    tx.vout[0].nValue = 42;

    block.vtx.resize(3);
    block.vtx[0] = tx;
    block.nVersion = 42;
    block.hashPrevBlock = GetRandHash();
    block.nBits = 0x207fffff;

    tx.vin[0].prevout.hash = GetRandHash();
    tx.vin[0].prevout.n = 0;
    block.vtx[1] = tx;

    tx.vin.resize(10);
    for (size_t i = 0; i < tx.vin.size(); i++) {
        tx.vin[i].prevout.hash = GetRandHash();
        tx.vin[i].prevout.n = 0;
    }
    block.vtx[2] = tx;

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    assert(!mutated);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;
    return block;
}

// Number of shared use_counts we expect for a tx we havent touched
// == 2 (mempool + our copy from the GetSharedTx call)
#define SHARED_TX_OFFSET 2

BOOST_AUTO_TEST_CASE(SimpleRoundTripTest)
{
    CTxMemPool pool(CFeeRate(0));
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());

    pool.addUnchecked(block.vtx[2].GetHash(), entry.FromTx(block.vtx[2]));
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

    // Do a simple ShortTxIDs RT
    {
        CBlockHeaderAndShortTxIDs shortIDs(block);

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << shortIDs;

        CBlockHeaderAndShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2) == READ_STATUS_OK);
        BOOST_CHECK( partialBlock.IsTxAvailable(0));
        BOOST_CHECK(!partialBlock.IsTxAvailable(1));
        BOOST_CHECK( partialBlock.IsTxAvailable(2));

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);

        std::list<CTransaction> removed;
        pool.removeRecursive(block.vtx[2], removed);
        BOOST_CHECK_EQUAL(removed.size(), 1);

        CBlock block2;
        std::vector<CTransaction> vtx_missing;
        BOOST_CHECK(partialBlock.FillBlock(block2, vtx_missing) == READ_STATUS_INVALID); // No transactions

        vtx_missing.push_back(block.vtx[2]); // Wrong transaction
        partialBlock.FillBlock(block2, vtx_missing); // Current implementation doesn't check txn here, but don't require that
        bool mutated;
        BOOST_CHECK(block.hashMerkleRoot != BlockMerkleRoot(block2, &mutated));

        vtx_missing[0] = block.vtx[1];
        CBlock block3;
        BOOST_CHECK(partialBlock.FillBlock(block3, vtx_missing) == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), block3.GetHash().ToString());
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block3, &mutated).ToString());
        BOOST_CHECK(!mutated);
    }
}

class TestHeaderAndShortIDs {
    // Utility to encode custom CBlockHeaderAndShortTxIDs
public:
    CBlockHeader header;
    uint64_t nonce;
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

    TestHeaderAndShortIDs(const CBlockHeaderAndShortTxIDs& orig) {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << orig;
        stream >> *this;
    }
    TestHeaderAndShortIDs(const CBlock& block) :
        TestHeaderAndShortIDs(CBlockHeaderAndShortTxIDs(block)) {}

    uint64_t GetShortID(const uint256& txhash) const {
        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << *this;
        CBlockHeaderAndShortTxIDs base;
        stream >> base;
        return base.GetShortID(txhash);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(header);
        READWRITE(nonce);
        size_t shorttxids_size = shorttxids.size();
        READWRITE(VARINT(shorttxids_size));
        shorttxids.resize(shorttxids_size);
        for (size_t i = 0; i < shorttxids.size(); i++) {
            uint32_t lsb = shorttxids[i] & 0xffffffff;
            uint16_t msb = (shorttxids[i] >> 32) & 0xffff;
            READWRITE(lsb);
            READWRITE(msb);
            shorttxids[i] = (uint64_t(msb) << 32) | uint64_t(lsb);
        }
        uint64_t prefilledtxn_size = (uint64_t)prefilledtxn.size();
        READWRITE(COMPACTSIZE(prefilledtxn_size));
        if (ser_action.ForRead()) {
            size_t i = 0;
            while (prefilledtxn.size() < prefilledtxn_size) {
                prefilledtxn.resize(std::min((uint64_t)(1000 + prefilledtxn.size()), prefilledtxn_size));
                for (; i < prefilledtxn.size(); i++) {
                    uint64_t index = 0;
                    READWRITE(COMPACTSIZE(index));
                    if (index > std::numeric_limits<uint16_t>::max())
                        throw std::ios_base::failure("index overflowed 16 bits");
                    prefilledtxn[i].index = index;
                    READWRITE(REF(TransactionCompressor(prefilledtxn[i].tx)));
                }
            }

            uint16_t offset = 0;
            for (size_t i = 0; i < prefilledtxn.size(); i++) {
                if (uint64_t(prefilledtxn[i].index) + uint64_t(offset) > std::numeric_limits<uint16_t>::max())
                    throw std::ios_base::failure("indexes overflowed 16 bits");
                prefilledtxn[i].index = prefilledtxn[i].index + offset;
                offset = prefilledtxn[i].index + 1;
            }
        }else {
            for (size_t i = 0; i < prefilledtxn.size(); i++) {
                uint64_t index = prefilledtxn[i].index - (i == 0 ? 0 : (prefilledtxn[i - 1].index + 1));
                READWRITE(COMPACTSIZE(index));
                READWRITE(REF(TransactionCompressor(prefilledtxn[i].tx)));
            }
        }
    }
};

BOOST_AUTO_TEST_CASE(NonCoinbasePreforwardRTTest)
{
    CTxMemPool pool(CFeeRate(0));
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());

    pool.addUnchecked(block.vtx[2].GetHash(), entry.FromTx(block.vtx[2]));
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

    // Test with pre-forwarding tx 1, but not coinbase
    {
        TestHeaderAndShortIDs shortIDs(block);
        shortIDs.prefilledtxn.resize(1);
        shortIDs.prefilledtxn[0] = {1, block.vtx[1]};
        shortIDs.shorttxids.resize(2);
        shortIDs.shorttxids[0] = shortIDs.GetShortID(block.vtx[0].GetHash());
        shortIDs.shorttxids[1] = shortIDs.GetShortID(block.vtx[2].GetHash());

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << shortIDs;

        CBlockHeaderAndShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2) == READ_STATUS_OK);
        BOOST_CHECK(!partialBlock.IsTxAvailable(0));
        BOOST_CHECK( partialBlock.IsTxAvailable(1));
        BOOST_CHECK( partialBlock.IsTxAvailable(2));

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);

        CBlock block2;
        std::vector<CTransaction> vtx_missing;
        BOOST_CHECK(partialBlock.FillBlock(block2, vtx_missing) == READ_STATUS_INVALID); // No transactions

        vtx_missing.push_back(block.vtx[1]); // Wrong transaction
        partialBlock.FillBlock(block2, vtx_missing); // Current implementation doesn't check txn here, but don't require that
        bool mutated;
        BOOST_CHECK(block.hashMerkleRoot != BlockMerkleRoot(block2, &mutated));

        vtx_missing[0] = block.vtx[0];
        CBlock block3;
        BOOST_CHECK(partialBlock.FillBlock(block3, vtx_missing) == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), block3.GetHash().ToString());
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block3, &mutated).ToString());
        BOOST_CHECK(!mutated);

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);
    }
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[2].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);
}

BOOST_AUTO_TEST_CASE(SufficientPreforwardRTTest)
{
    CTxMemPool pool(CFeeRate(0));
    TestMemPoolEntryHelper entry;
    CBlock block(BuildBlockTestCase());

    pool.addUnchecked(block.vtx[1].GetHash(), entry.FromTx(block.vtx[1]));
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[1].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);

    // Test with pre-forwarding coinbase + tx 2 with tx 1 in mempool
    {
        TestHeaderAndShortIDs shortIDs(block);
        shortIDs.prefilledtxn.resize(2);
        shortIDs.prefilledtxn[0] = {0, block.vtx[0]};
        shortIDs.prefilledtxn[1] = {2, block.vtx[2]};
        shortIDs.shorttxids.resize(1);
        shortIDs.shorttxids[0] = shortIDs.GetShortID(block.vtx[1].GetHash());

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << shortIDs;

        CBlockHeaderAndShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2) == READ_STATUS_OK);
        BOOST_CHECK( partialBlock.IsTxAvailable(0));
        BOOST_CHECK( partialBlock.IsTxAvailable(1));
        BOOST_CHECK( partialBlock.IsTxAvailable(2));

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[1].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);

        CBlock block2;
        std::vector<CTransaction> vtx_missing;
        BOOST_CHECK(partialBlock.FillBlock(block2, vtx_missing) == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), block2.GetHash().ToString());
        bool mutated;
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block2, &mutated).ToString());
        BOOST_CHECK(!mutated);

        BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[1].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 1);
    }
    BOOST_CHECK_EQUAL(pool.mapTx.find(block.vtx[1].GetHash())->GetSharedTx().use_count(), SHARED_TX_OFFSET + 0);
}

BOOST_AUTO_TEST_CASE(EmptyBlockRoundTripTest)
{
    CTxMemPool pool(CFeeRate(0));
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].scriptSig.resize(10);
    coinbase.vout.resize(1);
    coinbase.vout[0].nValue = 42;

    CBlock block;
    block.vtx.resize(1);
    block.vtx[0] = coinbase;
    block.nVersion = 42;
    block.hashPrevBlock = GetRandHash();
    block.nBits = 0x207fffff;

    bool mutated;
    block.hashMerkleRoot = BlockMerkleRoot(block, &mutated);
    assert(!mutated);
    while (!CheckProofOfWork(block.GetHash(), block.nBits, Params().GetConsensus())) ++block.nNonce;

    // Test simple header round-trip with only coinbase
    {
        CBlockHeaderAndShortTxIDs shortIDs(block);

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << shortIDs;

        CBlockHeaderAndShortTxIDs shortIDs2;
        stream >> shortIDs2;

        PartiallyDownloadedBlock partialBlock(&pool);
        BOOST_CHECK(partialBlock.InitData(shortIDs2) == READ_STATUS_OK);
        BOOST_CHECK(partialBlock.IsTxAvailable(0));

        CBlock block2;
        std::vector<CTransaction> vtx_missing;
        BOOST_CHECK(partialBlock.FillBlock(block2, vtx_missing) == READ_STATUS_OK);
        BOOST_CHECK_EQUAL(block.GetHash().ToString(), block2.GetHash().ToString());
        bool mutated;
        BOOST_CHECK_EQUAL(block.hashMerkleRoot.ToString(), BlockMerkleRoot(block2, &mutated).ToString());
        BOOST_CHECK(!mutated);
    }
}

BOOST_AUTO_TEST_CASE(TransactionsRequestSerializationTest) {
    BlockTransactionsRequest req1;
    req1.blockhash = GetRandHash();
    req1.indexes.resize(4);
    req1.indexes[0] = 0;
    req1.indexes[1] = 1;
    req1.indexes[2] = 3;
    req1.indexes[3] = 4;

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << req1;

    BlockTransactionsRequest req2;
    stream >> req2;

    BOOST_CHECK_EQUAL(req1.blockhash.ToString(), req2.blockhash.ToString());
    BOOST_CHECK_EQUAL(req1.indexes.size(), req2.indexes.size());
    BOOST_CHECK_EQUAL(req1.indexes[0], req2.indexes[0]);
    BOOST_CHECK_EQUAL(req1.indexes[1], req2.indexes[1]);
    BOOST_CHECK_EQUAL(req1.indexes[2], req2.indexes[2]);
    BOOST_CHECK_EQUAL(req1.indexes[3], req2.indexes[3]);
}

BOOST_AUTO_TEST_SUITE_END()
