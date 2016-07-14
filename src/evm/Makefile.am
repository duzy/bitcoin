evmdir = .

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)

if EMBEDDED_LEVELDB
LEVELDB_CPPFLAGS += -I$(srcdir)/../leveldb/include
LEVELDB_CPPFLAGS += -I$(srcdir)/../leveldb/helpers/memenv
endif

QUANTUM_EVM_INCLUDES = -I$(builddir)/.. $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)
QUANTUM_EVM_INCLUDES += -I$(srcdir)/include

LIBQUANTUM_DEVCORE=libquantum_devcore.a
LIBQUANTUM_DEVCRYPTO=libquantum_devcrypto.a
LIBQUANTUM_EVM=libquantum_evm.a
LIBQUANTUM_EVMCORE=libquantum_evmcore.a

evm_LIBRARIES =

if BUILD_QUANTUM_EVM_DEVCORE
evm_LIBRARIES += libquantum_devcore.a
endif

if BUILD_QUANTUM_EVM_DEVCRYPTO
evm_LIBRARIES += libquantum_devcrypto.a
endif

if BUILD_QUANTUM_EVM_ETHCORE
evm_LIBRARIES += libquantum_ethcore.a
endif

if BUILD_QUANTUM_EVM_ETHEREUM
evm_LIBRARIES += libquantum_ethereum.a
endif

if BUILD_QUANTUM_EVM_EVM
evm_LIBRARIES += libquantum_evm.a
endif

if BUILD_QUANTUM_EVM_EVMCORE
evm_LIBRARIES += libquantum_evmcore.a
endif

if BUILD_QUANTUM_EVM_EVMJIT
evm_LIBRARIES += libquantum_evmjit.a
endif

if BUILD_QUANTUM_EVM_DEVCORE
libquantum_devcore_a_CPPFLAGS = $(AM_CPPFLAGS) $(QUANTUM_EVM_INCLUDES)
libquantum_devcore_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libquantum_devcore_a_SOURCES = \
  libdevcore/Assertions.h \
  libdevcore/Base58.cpp \
  libdevcore/Base58.h \
  libdevcore/Base64.cpp \
  libdevcore/Base64.h \
  libdevcore/Common.cpp \
  libdevcore/CommonData.cpp \
  libdevcore/CommonData.h \
  libdevcore/Common.h \
  libdevcore/CommonIO.cpp \
  libdevcore/CommonIO.h \
  libdevcore/CommonJS.cpp \
  libdevcore/CommonJS.h \
  libdevcore/concurrent_queue.h \
  libdevcore/db.h \
  libdevcore/debugbreak.h \
  libdevcore/Diff.h \
  libdevcore/Exceptions.h \
  libdevcore/FileSystem.cpp \
  libdevcore/FileSystem.h \
  libdevcore/FixedHash.cpp \
  libdevcore/FixedHash.h \
  libdevcore/Guards.cpp \
  libdevcore/Guards.h \
  libdevcore/Hash.cpp \
  libdevcore/Hash.h \
  libdevcore/Log.cpp \
  libdevcore/Log.h \
  libdevcore/MemoryDB.cpp \
  libdevcore/MemoryDB.h \
  libdevcore/OverlayDB.cpp \
  libdevcore/OverlayDB.h \
  libdevcore/picosha2.h \
  libdevcore/RangeMask.cpp \
  libdevcore/RangeMask.h \
  libdevcore/RLP.cpp \
  libdevcore/RLP.h \
  libdevcore/SHA3.cpp \
  libdevcore/SHA3.h \
  libdevcore/Terminal.h \
  libdevcore/TransientDirectory.cpp \
  libdevcore/TransientDirectory.h \
  libdevcore/TrieCommon.cpp \
  libdevcore/TrieCommon.h \
  libdevcore/TrieDB.cpp \
  libdevcore/TrieDB.h \
  libdevcore/TrieHash.cpp \
  libdevcore/TrieHash.h \
  libdevcore/UndefMacros.h \
  libdevcore/vector_ref.h \
  libdevcore/Worker.cpp \
  libdevcore/Worker.h
endif

if BUILD_QUANTUM_EVM_DEVCRYPTO
libquantum_devcrypto_a_CPPFLAGS = $(AM_CPPFLAGS) $(QUANTUM_EVM_INCLUDES)
libquantum_devcrypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libquantum_devcrypto_a_SOURCES = \
  libdevcrypto/AES.cpp \
  libdevcrypto/AES.h \
  libdevcrypto/Common.cpp \
  libdevcrypto/Common.h \
  libdevcrypto/CryptoPP.cpp \
  libdevcrypto/CryptoPP.h \
  libdevcrypto/ECDHE.cpp \
  libdevcrypto/ECDHE.h \
  libdevcrypto/Exceptions.h \
  libdevcrypto/SecretStore.cpp \
  libdevcrypto/SecretStore.h \
  libdevcrypto/WordList.cpp \
  libdevcrypto/WordList.h
endif

if BUILD_QUANTUM_EVM_ETHCORE
libquantum_ethcore_a_CPPFLAGS = $(AM_CPPFLAGS) $(QUANTUM_EVM_INCLUDES)
libquantum_ethcore_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libquantum_ethcore_a_SOURCES = \
  libethcore/ABI.cpp \
  libethcore/ABI.h \
  libethcore/BasicAuthority.cpp \
  libethcore/BasicAuthority.h \
  libethcore/BlockHeader.cpp \
  libethcore/BlockHeader.h \
  libethcore/ChainOperationParams.cpp \
  libethcore/ChainOperationParams.h \
  libethcore/Common.cpp \
  libethcore/Common.h \
  libethcore/CommonJS.cpp \
  libethcore/CommonJS.h \
  libethcore/Exceptions.h \
  libethcore/ICAP.cpp \
  libethcore/ICAP.h \
  libethcore/KeyManager.cpp \
  libethcore/KeyManager.h \
  libethcore/Precompiled.cpp \
  libethcore/Precompiled.h \
  libethcore/SealEngine.cpp \
  libethcore/SealEngine.h \
  libethcore/Transaction.cpp \
  libethcore/Transaction.h
endif

if BUILD_QUANTUM_EVM_ETHEREUM
libquantum_ethereum_a_CPPFLAGS = $(AM_CPPFLAGS) $(QUANTUM_EVM_INCLUDES)
libquantum_ethereum_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libquantum_ethereum_a_SOURCES = \
  libethereum/Account.cpp \
  libethereum/AccountDiff.cpp \
  libethereum/AccountDiff.h \
  libethereum/Account.h \
  libethereum/All.h \
  libethereum/BasicGasPricer.cpp \
  libethereum/BasicGasPricer.h \
  libethereum/BlockChain.cpp \
  libethereum/BlockChain.h \
  libethereum/BlockChainSync.cpp \
  libethereum/BlockChainSync.h \
  libethereum/Block.cpp \
  libethereum/BlockDetails.cpp \
  libethereum/BlockDetails.h \
  libethereum/Block.h \
  libethereum/BlockQueue.cpp \
  libethereum/BlockQueue.h \
  libethereum/CachedAddressState.cpp \
  libethereum/CachedAddressState.h \
  libethereum/ChainParams.cpp \
  libethereum/ChainParams.h \
  libethereum/ClientBase.cpp \
  libethereum/ClientBase.h \
  libethereum/Client.cpp \
  libethereum/Client.h \
  libethereum/ClientTest.cpp \
  libethereum/ClientTest.h \
  libethereum/CommonNet.cpp \
  libethereum/CommonNet.h \
  libethereum/Defaults.cpp \
  libethereum/Defaults.h \
  libethereum/EthereumHost.cpp \
  libethereum/EthereumHost.h \
  libethereum/EthereumPeer.cpp \
  libethereum/EthereumPeer.h \
  libethereum/Executive.cpp \
  libethereum/Executive.h \
  libethereum/ExtVM.cpp \
  libethereum/ExtVM.h \
  libethereum/GasPricer.cpp \
  libethereum/GasPricer.h \
  libethereum/GenericFarm.h \
  libethereum/GenericMiner.cpp \
  libethereum/GenericMiner.h \
  libethereum/GenesisInfo.cpp \
  libethereum/GenesisInfo.h \
  libethereum/Interface.cpp \
  libethereum/Interface.h \
  libethereum/LogFilter.cpp \
  libethereum/LogFilter.h \
  libethereum/MiningClient.cpp \
  libethereum/MiningClient.h \
  libethereum/State.cpp \
  libethereum/State.h \
  libethereum/Transaction.cpp \
  libethereum/Transaction.h \
  libethereum/TransactionQueue.cpp \
  libethereum/TransactionQueue.h \
  libethereum/TransactionReceipt.cpp \
  libethereum/TransactionReceipt.h \
  libethereum/Utility.cpp \
  libethereum/Utility.h \
  libethereum/VerifiedBlock.h
endif

if BUILD_QUANTUM_EVM_EVM
libquantum_evm_a_CPPFLAGS = $(AM_CPPFLAGS) $(QUANTUM_EVM_INCLUDES)
libquantum_evm_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libquantum_evm_a_SOURCES = \
  libevm/All.h \
  libevm/ExtVMFace.cpp \
  libevm/ExtVMFace.h \
  libevm/JitEnv.cpp \
  libevm/JitUtils.h \
  libevm/JitVM.cpp \
  libevm/JitVM.h \
  libevm/SmartVM.cpp \
  libevm/SmartVM.h \
  libevm/VM.cpp \
  libevm/VMFace.h \
  libevm/VMFactory.cpp \
  libevm/VMFactory.h \
  libevm/VM.h
endif

if BUILD_QUANTUM_EVM_EVMCORE
libquantum_evmcore_a_CPPFLAGS = $(AM_CPPFLAGS) $(QUANTUM_EVM_INCLUDES)
libquantum_evmcore_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libquantum_evmcore_a_SOURCES = \
  libevmcore/EVMSchedule.cpp \
  libevmcore/EVMSchedule.h \
  libevmcore/Exceptions.h \
  libevmcore/Instruction.cpp \
  libevmcore/Instruction.h
endif

if BUILD_QUANTUM_EVM_EVMJIT
libquantum_evmjit_a_CPPFLAGS = $(AM_CPPFLAGS) $(QUANTUM_EVM_INCLUDES)
libquantum_evmjit_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libquantum_evmjit_a_SOURCES = \
  libevmjit/Arith256.cpp \
  libevmjit/Arith256.h \
  libevmjit/Array.cpp \
  libevmjit/Array.h \
  libevmjit/BasicBlock.cpp \
  libevmjit/BasicBlock.h \
  libevmjit/BuildInfo.gen.h \
  libevmjit/Cache.cpp \
  libevmjit/Cache.h \
  libevmjit/Common.h \
  libevmjit/Compiler.cpp \
  libevmjit/Compiler.h \
  libevmjit/CompilerHelper.cpp \
  libevmjit/CompilerHelper.h \
  libevmjit/Endianness.cpp \
  libevmjit/Endianness.h \
  libevmjit/ExecStats.cpp \
  libevmjit/ExecStats.h \
  libevmjit/Ext.cpp \
  libevmjit/Ext.h \
  libevmjit/GasMeter.cpp \
  libevmjit/GasMeter.h \
  libevmjit/Instruction.cpp \
  libevmjit/Instruction.h \
  libevmjit/JIT-c.cpp \
  libevmjit/JIT.cpp \
  libevmjit/Memory.cpp \
  libevmjit/Memory.h \
  libevmjit/Optimizer.cpp \
  libevmjit/Optimizer.h \
  libevmjit/RuntimeManager.cpp \
  libevmjit/RuntimeManager.h \
  libevmjit/Type.cpp \
  libevmjit/Type.h \
  libevmjit/Utils.cpp \
  libevmjit/Utils.h
endif

.PHONY: FORCE
