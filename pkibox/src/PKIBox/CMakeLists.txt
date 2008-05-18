
SET(PKIBOX_SOURCES
    Exception.cpp
    InvalidArgumentException.cpp
    PKIBox.cpp
    asn1/AlgorithmID.cpp
    asn1/Attribute.cpp
    asn1/AttributeValue.cpp
    asn1/DistinguishedName.cpp
    asn1/GeneralName.cpp
    asn1/KeyIdentifier.cpp
    asn1/ObjectID.cpp
    asn1/OIDs.cpp
    asn1/RelativeDistinguishedName.cpp
    openssl/Globals.cpp
    utils/ByteArray.cpp
)

SET(PKIBOX_HEADERS
    Exception.h
    InvalidArgumentException.h
    PKIBox.h
    asn1/AlgorithmID.h
    asn1/Attribute.h
    asn1/AttributeValue.h
    asn1/DistinguishedName.h
    asn1/GeneralName.h
    asn1/KeyIdentifier.h
    asn1/ObjectID.h
    asn1/OIDs.h
    asn1/RelativeDistinguishedName.h
    openssl/Globals.h
    utils/ByteArray.h
)

INSTALL(FILES ${PKIBOX_HEADERS}
    DESTINATION "include/podofo/PKIBox"
    )

 
MESSAGE("Building static PKIBox library")
ADD_LIBRARY(pkibox_static STATIC ${PKIBOX_SOURCES})
TARGET_LINK_LIBRARIES(pkibox_static ${PKIBOX_LIB_DEPENDS})

SET_TARGET_PROPERTIES(pkibox_static PROPERTIES
        VERSION "0.0.1"
        SOVERSION "0.0.1"
        CLEAN_DIRECT_OUTPUT 1
        OUTPUT_NAME "pkibox"
        )

SET(PKIBOX_DEPEND_TARGET pkibox_static
  CACHE INTERNAL "Which PKIBox library variant to depend on")

INSTALL(TARGETS pkibox_static
  RUNTIME DESTINATION "bin"
  LIBRARY DESTINATION "${LIBDIRNAME}"
  ARCHIVE DESTINATION "${LIBDIRNAME}"
  )
