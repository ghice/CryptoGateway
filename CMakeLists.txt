IF(NOT CRYPTOGATEWAY_CMAKE)
SET(CRYPTOGATEWAY_CMAKE 1)

INCLUDE(${GLOBAL_DIR}/Datastructures/CMakeLists.txt)
INCLUDE(${GLOBAL_DIR}/UnitTest/CMakeLists.txt)
INCLUDE(${GLOBAL_DIR}/osMechanics/CMakeLists.txt)

MESSAGE(STATUS )
MESSAGE(STATUS ========= CryptoGateway ==========)
MESSAGE(STATUS )

SET(EXE_LIBS ${EXE_LIBS} CryptoGateway)
SET(CUR_SRC ${GLOBAL_DIR}/CryptoGateway)
INCLUDE_DIRECTORIES(${CUR_SRC})

SET( SRC_H
	${CUR_SRC}/CryptoGateway.h
	${CUR_SRC}/cryptoLogging.h
	${CUR_SRC}/file_mechanics.h
	${CUR_SRC}/interior_message.h
	${CUR_SRC}/large_number.h
	${CUR_SRC}/public_key.h
	${CUR_SRC}/RC4_Hash.h
	${CUR_SRC}/streamCipher.h
	${CUR_SRC}/security_gateway.h
	${CUR_SRC}/securitySpinLock.h
	${CUR_SRC}/cryptoFrameworks.h
	${CUR_SRC}/cryptoException.h

	${CUR_SRC}/cryptoNumber.h
	${CUR_SRC}/cryptoHash.h
	${CUR_SRC}/cryptoPublicKey.h

	${CUR_SRC}/binaryEncryption.h
	${CUR_SRC}/XMLEncryption.h

	${CUR_SRC}/cryptoError.h
	${CUR_SRC}/streamPackage.h
	${CUR_SRC}/publicKeyPackage.h

	${CUR_SRC}/cryptoConstants.h
	${CUR_SRC}/cryptoCHeaders.h
	${CUR_SRC}/hexConversion.h
)

SET( SRC_CPP
	${CUR_SRC}/cryptoLogging.cpp
	${CUR_SRC}/interior_message.cpp
	${CUR_SRC}/large_number.cpp
	${CUR_SRC}/public_key.cpp
	${CUR_SRC}/RC4_Hash.cpp
	${CUR_SRC}/streamCipher.cpp
	${CUR_SRC}/security_gateway.cpp
	${CUR_SRC}/securitySpinLock.cpp
	${CUR_SRC}/cryptoFrameworks.cpp

	${CUR_SRC}/cryptoNumber.cpp
	${CUR_SRC}/cryptoHash.cpp
	${CUR_SRC}/cryptoPublicKey.cpp

	${CUR_SRC}/binaryEncryption.cpp
	${CUR_SRC}/XMLEncryption.cpp

	${CUR_SRC}/cryptoError.cpp
	${CUR_SRC}/streamPackage.cpp
	${CUR_SRC}/publicKeyPackage.cpp

	${CUR_SRC}/cryptoConstants.cpp
	${CUR_SRC}/cryptoCSource.cpp
	${CUR_SRC}/hexConversion.cpp
)

ADD_LIBRARY( CryptoGateway STATIC
	${SRC_CPP}
	${SRC_H}
)
INCLUDE(${GLOBAL_DIR}/CryptoGateway/test/CMakeLists.txt)

ENDIF(NOT CRYPTOGATEWAY_CMAKE)