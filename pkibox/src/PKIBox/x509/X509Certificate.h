
#ifndef PKIBOX_X509_X509_CERTIFICATE_H
#define PKIBOX_X509_X509_CERTIFICATE_H

typedef struct x509_st X509;

#include <memory>
#include <string>
#include <vector>
#include "../utils/clone_ptr.h"
#include "../security/cert/Certificate.h"

namespace PKIBox
{
	namespace utils
	{
		class ByteArray;
		class BigInteger;
		class DateTime;
	}

	namespace security
	{
		namespace cert
		{
			class Certificate;
		}
		
	}

	namespace asn1
	{
		class ObjectID;
		class DistinguishedName;
		class AlgorithmID;
	}

	namespace ocsp
	{
		class CCertID;
		class CRequest;
		class COCSPRequest;
		class CBasicOCSPResponse;
	}

	namespace pkcs6
	{
		class CExtendedCertificate;
	}

	namespace pkcs7
	{
		class CSignedData;
		class CEnvelopedData;
		class CContentInfo;
		class CRecipientInfo;
		class CSignedAndEnvelopedData;
	}

	namespace pkcs11
	{
		class CCertificate;
	}

	namespace pkcs12
	{
		class CCertificateBag;
		class CPKCS12;
	}

	namespace cms
	{
		class CCertfificateSet;
		class CSignedData;
	}

	//! This namespace provides classes for X509 certificate and crl processing.
	namespace x509
	{
		// Forward declarations
		class PublicKey;
		class PrivateKey;
		class X509CRLEntry;
		class X509Extension;

		//! This class represents an X509 Certificate.
		/*!
			A certificate can be imagined as some kind of "digital identity card" attesting that 
			a particular public key belongs to a particular entity. Certificates have a limited 
			period of validity and are digitally signed by some trusted authority. Certificates 
			can be verified by anyone having access to the signing authority´s public key.

			The ASN.1 syntax of X509Certificate is

			Certificate  ::=  SEQUENCE  {<br>
			tbsCertificate       TBSCertificate,<br>
			signatureAlgorithm   AlgorithmIdentifier,<br>
			signatureValue       BIT STRING  }<br>

			TBSCertificate  ::=  SEQUENCE  {<br>
			version         [0]  EXPLICIT Version DEFAULT v1,<br>
			serialNumber         CertificateSerialNumber,<br>
			signature            AlgorithmIdentifier,<br>
			issuer               Name,<br>
			validity             Validity,<br>
			subject              Name,<br>
			subjectPublicKeyInfo SubjectPublicKeyInfo,<br>
			issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version must be v2 or v3<br>
			subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL, -- If present, version must be v2 or v3<br>
			extensions      [3]  EXPLICIT Extensions OPTIONAL -- If present, version must be v3}<br>

		*/
		class X509Certificate : public security::cert::Certificate
		{
			friend class X509CRLEntry;
			friend class ocsp::CCertID;
			friend class ocsp::CRequest;
			friend class ocsp::COCSPRequest;
			friend class ocsp::CBasicOCSPResponse;
			friend class pkcs6::CExtendedCertificate;
			friend class pkcs7::CContentInfo;
			friend class pkcs7::CSignedData;
			friend class pkcs7::CEnvelopedData;
			friend class pkcs7::CRecipientInfo;
			friend class pkcs7::CSignedAndEnvelopedData;
			friend class pkcs11::CCertificate;
			friend class pkcs12::CCertificateBag;
			friend class pkcs12::CPKCS12;
			friend class cms::CSignedData;
			friend class cms::CCertfificateSet;

		public:
			//! Default constructor. Assigns m_pCert to NULL.
			X509Certificate(void);

			//! Constructs a X509Certificate from the DER/PEM encoded buffer.
			/*!
				\param unsigned char *pbArray: DER/PEM certificate buffer 
				\param unsigned int cLength: Input buffer length
			*/
			X509Certificate(/*const */unsigned char *pbArray, unsigned int cLength) /* throw (CException)*/;

			//! Constructs a X509Certificate from the DER/PEM encoded ByteArray. 
			/*!
				The following sample lines loads the data from the file and store in the byte array and creates the certificate from that byte array
				utils::ByteArray baCertificate = File::Load("C:\\Certificate.cer");
				X509Certificate certificate(baCertificate);

				\param const utils::ByteArray &ByteArray: Byte array containing the DER/PEM encoded certificate data
			*/
			explicit X509Certificate(const utils::ByteArray &ByteArray) /* throw (CException)*/;

			//! Constructs a X509Certificate from the DER/PEM encoded file.
			/*!
				The following sample creates the certificate object from file
				X509Certificate certificate("C:\\Certificate.cer");

				\param const char *szFileName: path of the file to construct certificate object from
			*/
			explicit X509Certificate(const char *szFileName) /* throw (CException)*/;

			virtual ~X509Certificate(void);

			//! Copy constructor.
			/*!
				\param const X509Certificate &rhs
			*/
			X509Certificate(const X509Certificate &rhs);

			//! Copy Assignment operator.
			/*!
				\param const X509Certificate &rhs
				\return X509Certificate &
			*/
			X509Certificate &operator=(const X509Certificate &rhs);

			//! Assigns a DER encoded byte array to this X509Certificate.
			/*!
				\param const utils::ByteArray &baCert: Byte array containing the certificate bytes
				\return X509Certificate &
			*/
			X509Certificate &operator=(const utils::ByteArray &baCert);

			//! Returns this X509Certificate as DER encoded ASN.1 data structure. 
			/*!
				\return utils::ByteArray: a byte array holding the DER encoded X509 certificate ASN.1 data structure
			*/
			utils::ByteArray GetEncoded() const /* throw (CException) */;

			//! Constructs a X509Certificate from PEM buffer. Any previous Certificate data will be deleted. 
			/*!
				\param const utils::ByteArray &PEMData: a byte array containing the PEM encoded certificate bytes
			*/
			void FromPEM(const utils::ByteArray &PEMData) /* throw (CException) */; 

			//! Constructs a X509Certificate from DER buffer. Any previous Certificate data will be deleted.
			/*!
				\param const utils::ByteArray &DERData: a byte array containing the DER encoded certificate bytes
			*/
			void FromDER(const utils::ByteArray &DERData) /* throw (CException) */; 

			//! Returns true if this X509Certificate is a CA certificate. 
			/*!
				\return bool: true, certificate belongs to some CA
			*/
			bool IsCACert() const /* throw (CException)*/;

			//! Returns true if this X509Certificate is self signed certificate. 
			/*!
				\return bool: true, if certificate is selfsigned
			*/
			bool IsSelfSigned() const /* throw (CException)*/;

			//! Returns true if this X509Certificate is a Root CA certificate. 
			//	bool IsRootCACert() const /* throw (CException)*/;

			//! Returns the version number of this X509Certificate. 
			/*!
				\return int: version number of the certificate as int, 1 for a v1 cert, 2 for a v2 cert, and 3 for a v3 cert
			*/
			int GetVersion() const /* throw (CException)*/;

			//! Sets the version number of the X509Certificate.
			/*!
				\param unsigned int iVersion: version number of the certificate as int, 1 for a v1 cert, 2 for a v2 cert, and 3 for a v3 cert
			*/
			void SetVersion(unsigned int iVersion) /* throw (CException)*/ ; 

			//! Returns the Subject Distinguished Name of this X509Certificate. 
			/*!
				\return asn1::DistinguishedName: the distinguished name of the subject of this certificate
			*/
			asn1::DistinguishedName GetSubjectDN() const /* throw (CException)*/ ;

			//! Sets the Subject Distinguished Name of this X509Certificate.
			/*!
				\param const asn1::DistinguishedName &subjectDN: the distinguished name of the subject of this certificate as 
			*/
			void SetSubjectDN(const asn1::DistinguishedName &subjectDN) /* throw (CException)*/ ;

			//! Returns the Issuer Distinguished Name of this X509Certificate. 
			/*!
				\return asn1::DistinguishedName: the distinguished name of the issuer of this certificate
			*/
			asn1::DistinguishedName GetIssuerDN() const /* throw (CException)*/;

			//! Sets the Issuer Distinguished Name of this X509Certificate.
			/*!
				\param const asn1::DistinguishedName &IssuerDN: the distinguished name of the issuer of this certificate
			*/
			void SetIssuerDN(const asn1::DistinguishedName &IssuerDN) /* throw (CException)*/ ;

			//! Returns the serial number of this X509Certificate. 
			/*!
				\return utils::BigInteger: serial number of the certificate
			*/
			utils::BigInteger GetSerialNumber() const /* throw (CException)*/;

			//! Sets the serial number of this X509Certificate.
			/*!
				\param const utils::BigInteger &serialNumber: serial number of the certificate
			*/
			void SetSerialNumber(const utils::BigInteger &serialNumber) /* throw (CException)*/ ;

			//! Returns the NotBefore date of this X509Certificate. 
			/*!
				\return utils::DateTime: the date on which this certificate becomes valid, or null if the notBefore date has yet not been set
			*/
			utils::DateTime GetNotBefore() const /* throw (CException)*/;

			//! Sets the NotBefore date of the X509Certificate.
			/*!
				\param const utils::DateTime &notBefore: the date on which this certificate becomes valid
			*/
			void SetNotBefore(const utils::DateTime &notBefore) /* throw (CException)*/;

			//! Returns the NotAfter date of this X509Certificate. 
			/*!
				\return utils::DateTime: the date on which the certificate´s validity expires, or null if the notAfter date has yet not been set
			*/
			utils::DateTime GetNotAfter() const /* throw (CException)*/;

			//! Sets the NotAfter date of this X509Certificate.
			/*!
				\param const utils::DateTime &notAfter: the date on which the certificate´s validity expires
			*/
			void SetNotAfter(const utils::DateTime &notAfter) /* throw (CException)*/;

			//! Returns the Public key of this X509Certificate. 
			/*!
				\return PublicKey: the public key of the certificate
			*/
			PublicKey GetPublicKey() const /* throw (CExceptoin) */;

			//! Sets the Public key of this X509Certificate.
			/*!
				\param const PublicKey &pKey: the public key of the certificate
			*/
			void SetPublicKey(const PublicKey &pKey) /* throw (CException)*/;

			//! Returns the signature algorithm of this X509Certificate. 
			/*!
				\return std::auto_ptr<asn1::AlgorithmID>: the AlgorithmID of the signature algorithm used for signing this certificate
			*/
			std::auto_ptr<asn1::AlgorithmID> GetSignatureAlgorithm() const /* throw (CExceptoin) */ ;

			//! Sets the signature algorithm of this X509Certificate.
			/*!
				\param const asn1::AlgorithmID &algID: the AlgorithmID of the signature algorithm used for signing this certificate
			*/
			void SetSignatureAlgorithm(const asn1::AlgorithmID &algID) /* throw (CException)*/;

			//! Returns the signature of this X509Certificate. 
			/*!
				\return utils::ByteArray: the signature value as byte array
			*/
			utils::ByteArray GetSignature() const /* throw (CExceptoin) */ ;

			//! Sets the signature of this X509Certificate.
			/*!
				\param const utils::ByteArray &baSignature: the signature value as byte array
			*/
			void SetSignature(const utils::ByteArray &baSignature) /* throw (CException)*/;

			//! Returns true if there are any extensions in this X509Certificate.
			/*!
				\return bool: true, if this certificate has extensions
			*/
			bool HasExtensions() const /* throw (CExceptoin) */;

			//! Returns the number of extensions of this X509Certificate.
			/*!
				\return unsigned int: number of extensions present in the certificate
			*/
			unsigned int GetNumberOfExtensions() const;

			//! Returns an array of all extensions included in this X509Certificate. 
			/*!
				\return std::vector< clone_ptr<x509::X509Extension> >: the extensions present in the certificate
			*/
			std::vector< clone_ptr<x509::X509Extension> > GetExtensions() const /* throw (CExceptoin) */;

			//! Returns the extension of this X509Certificate by object identifier. 
			/*!
				\param const asn1::ObjectID &OID: the object ID of the extension
				\return std::auto_ptr<X509Extension>: the desired extension or null if the requested extension is not present
			*/
			std::auto_ptr<X509Extension> GetExtension(const asn1::ObjectID &OID) const /* throw (CExceptoin) */;

			//! Adds the given X509v3 extension in this X509Certificate. 
			/*!
				The following sample code demonstrates adding the basic constraint extension
				CBasicConstraints bc = new CBasicConstraints(true, 1);
				bc.setCritical(true);
				cert.addExtension(bc);


				\param const X509Extension &extension: the X509v3 extension to add to the list of extensions
			*/
			void AddExtension(const X509Extension &extension) /* throw (CException)*/;

			//! Removes the extension specified by its object identifier from this X509Certificate.
			/*!
				\param const asn1::ObjectID &OID: Object Id of the extension to be removed
			*/
			void RemoveExtension(const asn1::ObjectID &OID) /* throw (CException)*/;

			//! Removes all extensions from this X509Certificate.
			void RemoveAllExtensions()/* throw (CException)*/;

			//! Returns the PEM encoding of this X509Certificate. 
			/*!
				\return utils::ByteArray: a byte array containing the PEM encoded certificate bytes
			*/
			utils::ByteArray ToPEM() const /* throw (CException) */;

			//! Writes the PEM/DER encoded form of this X509Certificate to disk.
			/*!
				\param szFileName Name of the file on disk.
				\param bPEM Whether to write in PEM format or not? If it is false then DER encoding will be written on the disk. By default its value is false.
				\returns true if this X509Certificate is successfully written to disk otherwise throws CException. If an 
				exception is thrown, then the return value is meaningless.
			*/
			bool WriteToDisk(const std::string &szFileName, bool bPEM = false) /* throw (CException) */;

			//! Signs a certificate using the given algorithm and the private key of the issuer.
			/*!
				\param const asn1::AlgorithmID &algID: the AlgorithmID of the signature algorithm
				\param const PrivateKey &pKey: the private key of the issuer
			*/
			void Sign(const asn1::AlgorithmID &algID, const PrivateKey &pKey) /* throw (CException)*/;

			//! Verifies a certificate using the given public key. 
			/*!
				\param Key Public Key for verification.
				\returns true if this X509Certificate is successfully verified otherwise throws CExecption. If an 
				exception is thrown, then the return value is meaningless.
			*/
			bool Verify(PublicKey &Key) /* throw (CExceptoin) */;

			//! Verifies a certificate using the public key of IssuerCert. 
			/*!
				\param const X509Certificate &IssuerCert: issuer's certificate for verification
			*/
			bool Verify(const X509Certificate &IssuerCert) /* throw (CExceptoin) */;

			//! Equality operator. Returns true if the DER encoded representation of both certificates is identical. 
			/*!
				\param const X509Certificate &rhs
				\return bool: true, if this certificate and the certificate in parameters are equal
			*/
			bool operator==(const X509Certificate &rhs);

			//! InEquality operator. Returns true if the DER encoded representation of both certificates is not identical. 
			/*!
				\param const X509Certificate &rhs
				\return bool: true, this certificate and the certificate in parameter are not equal
			*/
			bool operator!=(const X509Certificate &rhs);

		private:
			bool IsDER(const unsigned char *pbArray);
			void Construct(const unsigned char *pbArray, unsigned int cLength) /* throw (CException) */ ;

			X509 *m_pCert; // Underlying pointer to OpenSSL structure.
		};
	}
}

#endif // !PKIBOX_X509_X509_CERTIFICATE_H

