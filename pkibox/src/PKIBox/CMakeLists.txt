
SET(PKIBOX_SOURCES
    Exception.cpp
    InvalidArgumentException.cpp
    NullPointerException.cpp
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
    security/Key.cpp
    security/cert/Certificate.cpp
    utils/ArithmeticException.cpp
    utils/BigInteger.cpp
    utils/ByteArray.cpp
    utils/DateTime.cpp
    utils/File.cpp
    utils/TimeSpan.cpp
    x509/PrivateKey.cpp
    x509/PublicKey.cpp
    x509/PublicKeyInfo.cpp
    x509/X509Certificate.cpp
    x509/X509CRL.cpp
    x509/X509CRLEntry.cpp
    x509/X509Extension.cpp
    x509/extensions/AccessDescription.cpp
    x509/extensions/AuthorityInformationAccess.cpp
    x509/extensions/BasicConstraints.cpp
    x509/extensions/CertificatePolicies.cpp
    x509/extensions/CRLDistributionPoint.cpp
    x509/extensions/CRLDistributionPoints.cpp
    x509/extensions/CRLNumber.cpp
    x509/extensions/DeltaCRLIndicator.cpp
    x509/extensions/ExtendedKeyUsage.cpp
    x509/extensions/HoldInstructionCode.cpp
    x509/extensions/InvalidityDate.cpp
    x509/extensions/IssuerAltName.cpp
    x509/extensions/KeyUsage.cpp
    x509/extensions/NoticeReference.cpp
    x509/extensions/PolicyInformation.cpp
    x509/extensions/PolicyQualifierInfo.cpp
    x509/extensions/ReasonCode.cpp
    x509/extensions/SubjectAltName.cpp
    x509/extensions/SubjectKeyIdentifier.cpp
    x509/extensions/UserNotice.cpp    
)

SET(PKIBOX_HEADERS
    Exception.h
    InvalidArgumentException.h
    NullPointerException.h
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
    security/Key.h
    security/cert/Certificate.h
    utils/ArithmeticException.h
    utils/BigInteger.h
    utils/ByteArray.h
    utils/clone_ptr.h
    utils/DateTime.h
    utils/File.h
    utils/TimeSpan.h
    x509/PrivateKey.h
    x509/PublicKey.h
    x509/PublicKeyInfo.h
    x509/X509CertChain.h
    x509/X509Certificate.h
    x509/X509CRL.h
    x509/X509CRLEntry.h
    x509/X509Extension.h
    x509/extensions/AccessDescription.h
    x509/extensions/AuthorityInformationAccess.h
    x509/extensions/BasicConstraints.h
    x509/extensions/CertificatePolicies.h
    x509/extensions/CRLDistributionPoint.h
    x509/extensions/CRLDistributionPoints.h
    x509/extensions/CRLNumber.h
    x509/extensions/DeltaCRLIndicator.h
    x509/extensions/ExtendedKeyUsage.h
    x509/extensions/HoldInstructionCode.h
    x509/extensions/InvalidityDate.h
    x509/extensions/IssuerAltName.h
    x509/extensions/KeyUsage.h
    x509/extensions/NoticeReference.h
    x509/extensions/PolicyInformation.h
    x509/extensions/PolicyQualifierInfo.h
    x509/extensions/ReasonCode.h
    x509/extensions/SubjectAltName.h
    x509/extensions/SubjectKeyIdentifier.h
    x509/extensions/UserNotice.h
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
