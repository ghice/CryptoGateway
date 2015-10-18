IF(NOT CRYPTOGATEWAY_CMAKE)
SET(CRYPTOGATEWAY_CMAKE 1)

INCLUDE(${GLOBAL_DIR}/Datastructures/CMakeLists.txt)

MESSAGE(STATUS )
MESSAGE(STATUS ========= CryptoGateway ==========)
MESSAGE(STATUS )

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
	${CUR_SRC}/RC4.h
	${CUR_SRC}/security_gateway.h
	${CUR_SRC}/streamCode.h
	${CUR_SRC}/securitySpinLock.cpp
)

SET( SRC_CPP
	${CUR_SRC}/cryptoLogging.cpp
	${CUR_SRC}/interior_message.cpp
	${CUR_SRC}/large_number.cpp
	${CUR_SRC}/public_key.cpp
	${CUR_SRC}/RC4_Hash.cpp
	${CUR_SRC}/RC4.cpp
	${CUR_SRC}/security_gateway.cpp
	${CUR_SRC}/streamCode.cpp
	${CUR_SRC}/securitySpinLock.h
)

ADD_LIBRARY( CryptoGateway STATIC
	${SRC_CPP}
	${SRC_H}
)

TARGET_LINK_LIBRARIES( CryptoGateway Datastructures )

ENDIF(NOT CRYPTOGATEWAY_CMAKE)