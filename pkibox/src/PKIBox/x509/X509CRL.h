
#ifndef PKIBOX_X509_X509_CRL_H
#define PKIBOX_X509_X509_CRL_H

typedef struct X509_crl_st X509_CRL;

#include <vector>
#include <memory>
#include <string>
#include "../utils/clone_ptr.h"

namespace PKIBox
{
	namespace utils
	{
		class DateTime;
		class ByteArray;
		class BigInteger;
	}

	namespace asn1
	{
		class ObjectID;
		class DistinguishedName;
		class AlgorithmID;
	}

	namespace pkcs7
	{
		class CSignedData;
		class CSignedAndEnvelopedData;
	}

	namespace pkcs12
	{
		class CCRLBag;
	}

	namespace cms
	{
		class CSignedData;
	}

	namespace x509
	{
		class X509Extension;
		class CX509Extensions;
		class PublicKey;
		class PrivateKey;
		class X509Certificate;
		class X509CRLEntry;

		//! This class represents an X509 Certificate Revocation List
		/*!
			Certificate Revocation List (CRL) denotes a list of certificates that have been expired for 
			some reason (e.g. the name of the subject has changed, the private key can no more being 
			treated to be only known by the subject, ...) prior to the regular ending of its validity period.

			The ASN.1 syntax of X509CRL is

			CertificateList  ::=  SEQUENCE  {
				tbsCertList          TBSCertList,
				signatureAlgorithm   AlgorithmIdentifier,
				signatureValue       BIT STRING  }

			TBSCertList  ::=  SEQUENCE  {
				version                 Version OPTIONAL, -- if present, must be v2
				signature               AlgorithmIdentifier,
				issuer                  Name,
				thisUpdate              Time,
				nextUpdate              Time OPTIONAL,
				revokedCertificates     SEQUENCE OF SEQUENCE  {
				userCertificate         CertificateSerialNumber,
				revocationDate          Time,
				crlEntryExtensions      Extensions OPTIONAL	-- if present, must be v2}  OPTIONAL,
				crlExtensions           [0]  EXPLICIT Extensions OPTIONAL -- if present, must be v2	}
		*/
		class X509CRL  
		{
			friend class pkcs7::CSignedData;
			friend class pkcs7::CSignedAndEnvelopedData;
			friend class pkcs12::CCRLBag;
			friend class cms::CSignedData;

		public:

			//! Default constructor. Initializes m_pCRL to NULL. 
			X509CRL();

			//! Constructs a X509CRL from the DER/PEM encoded buffer.
			/*!
				\param unsigned char *pbArray: DER/PEM encoded CRL bytes
				\param unsigned int cLength: length of DER/PEM encoded CRL bytes
			*/
			X509CRL(/*const */unsigned char *pbArray, unsigned int cLength) /* throw (CException) */;

			//! Constructs a X509CRL from the DER/PEM encoded ByteArray.
			/*!
				\param const utils::ByteArray &ByteArray: a byte array containing the PEM/DER encoded CRL bytes
			*/
			explicit X509CRL(const utils::ByteArray &ByteArray) /* throw (CException) */;

			//! Constructs a X509Certificate from the DER/PEM encoded file.
			/*!
				\param const char *szFileName: path of the file from which to construct the CRL object
			*/
			explicit X509CRL(const char *szFileName) /* throw (CException) */;

			virtual ~X509CRL();

			//! Copy constructor. 
			/*!
				\param const X509CRL &rhs
			*/
			X509CRL(const X509CRL &rhs);

			//! Assignment operator. 
			/*!
				\param const X509CRL &rhs
				\return X509CRL &
			*/
			X509CRL &operator=(const X509CRL &rhs);

			//! Returns this X509CRL as DER encoded ASN.1 data structure.
			/*!
				\return utils::ByteArray: a byte array containing the DER encoded CRL bytes
			*/
			utils::ByteArray GetEncoded() const /* throw (CException) */;

			//! Constructs a X509CRL from PEM buffer. Any previous CRL data will be deleted.
			/*!
				\param const utils::ByteArray &PEMData: a byte array containing the PEM encoded CRL bytes
			*/
			void FromPEM(const utils::ByteArray &PEMData) /* throw (CException) */; 

			//! Constructs a X509CRL from DER buffer. Any previous CRL data will be deleted. 
			/*!
				\param const utils::ByteArray &DERData: a byte array containing the DER encoded CRL bytes
			*/
			void FromDER(const utils::ByteArray &DERData) /* throw (CException) */; 

			//! Returns the version number of this X509CRL.
			/*!
				\return int: version number of this CRL, as int
			*/
			int GetVersion() const /* throw (CException) */;

			//! Sets the version number of the X509CRL.
			/*!
				\param unsigned int iVersion: version number of this CRL, as int
			*/
			void SetVersion(unsigned int iVersion) /* throw (CException)*/ ; 

			//! Returns the Issuer DN of this X509CRL.
			/*!
				\return asn1::DistinguishedName: the distinguished name of the issuer of the CRL
			*/
			asn1::DistinguishedName GetIssuerDN() const /* throw (CException) */;

			//! Sets the issuer of this CRL.
			/*!
				\param const asn1::DistinguishedName &issuer: the distinguished name of the issuer of the CRL
			*/
			void SetIssuerDN(const asn1::DistinguishedName &issuer);
				
			//! Returns ThisUpdate date of this X509CRL.
			/*!
				\return utils::DateTime: the date when this CRL has been issued
			*/
			utils::DateTime GetThisUpdate() const /* throw (CException) */;

			//! Sets the date of thisUpdate.
			/*!
				\param const utils::DateTime &thisUpdate: the date when this CRL has been issued
			*/
			void SetThisUpdate(const utils::DateTime &thisUpdate);
				
			//! Returns NextUpdate date of this X509CRL.
			/*!
				\return utils::DateTime: the date when the next CRL will be issued
			*/
			utils::DateTime GetNextUpdate() const /* throw (CException) */;

			//! Sets the date of nextUpdate.
			/*!
				\param const utils::DateTime &nextUpdate: the date when the next CRL will be issued
			*/
			void SetNextUpdate(const utils::DateTime &nextUpdate);
				
			//! Returns the signature algorithm of this X509CRL. 
			/*!
				\return std::auto_ptr<asn1::AlgorithmID>: the AlgorithmID of the signature algorithm 
			*/
			std::auto_ptr<asn1::AlgorithmID> GetSignatureAlgorithm() const /* throw (CExceptoin) */ ;

			//! Returns signature of this X509CRL.
			/*!
				\return utils::ByteArray: the signature value as byte array
			*/
			utils::ByteArray GetSignature() const /* throw (CException) */; 

			//! Checks if the certificate identified by the given serial number is marked as revoked by this CRL.
			/*!
				\param const utils::BigInteger &serialNumber: the serial number of the certificate which is checked of being revoked
				\return bool: true if the certificate identified by the given serial number is marked as revoked by this CRL, false if not
			*/
			bool IsRevoked(const utils::BigInteger &serialNumber);
				
			//! Checks whether the given certificate is on this CRL.
			/*!
				\param const X509Certificate &cert: the certificate to check for
				\return bool: true if the given certificate is on this CRL, false otherwise
			*/
			bool IsRevoked(const X509Certificate &cert);
				
			//! Returns an array of all the revoked certificates included into this CRL. 
			/*!
				\return std::vector<X509CRLEntry>: a Set of RevokedCertificate objects representing the certificates revoked by this CRL
			*/
			std::vector<X509CRLEntry> GetRevokedCertificates() const /* throw (CException) */;

			//! Sets an array of revoked certificates into this CRL. 
			/*!
				\param const std::vector<X509CRLEntry> &revokedCerts: a Set of RevokedCertificate objects representing the certificates revoked by this CRL
			*/
			void SetRevokedCertificates(const std::vector<X509CRLEntry> &revokedCerts) /* throw (CException) */;

			//! Returns a revoked certificate by serial number if found in this X509CRL. 
			/*!
				\param const utils::BigInteger &serialNumber: the serial number to be searched for
				\return std::auto_ptr<X509CRLEntry>: the RevokedCertificate belonging to the given serial number, if included into this CRL; null otherwise
			*/
			std::auto_ptr<X509CRLEntry> GetRevokedCertificate(const utils::BigInteger &serialNumber) const /* throw (CException) */;

			//! Adds a revoked certificate to the CRL.
			/*!
				\param const X509CRLEntry &revokedCert: the RevokedCertificate CRLEntry to add to this CRL
			*/
			void AddCertificate(const X509CRLEntry &revokedCert);
				
			//! Adds a certificate to the CRL to be revoked on the given date.
			/*!
				\param const X509Certificate &cert: the X509Certificate which should be revoked
				\param const utils::DateTime &revocationDate: the revocation date
			*/
			void AddCertificate(const X509Certificate &cert, const utils::DateTime &revocationDate);

			//! Removes the certificate with the given serial number from the CRL.  
			/*!
				\param const utils::BigInteger &serialNumber: the serial number of the certificate which should be removed
				\return bool: true if the certificate successfully has been removed false otherwise
			*/
			bool RemoveCertificate(const utils::BigInteger &serialNumber);

			//! Removes the certificate from the CRL. 
			/*!
				\param const X509Certificate &cert: X509Certificate to be removed from the CRL
				\return bool: true if the certificate successfully has been removed false otherwise
			*/
			bool RemoveCertificate(const X509Certificate &cert);

			//! Removes all certificates from the CRL. 
			void RemoveAllCertificates();
				
			//! Returns true if there are extensions included in this X509CRL.
			/*!
				\return bool: true if there are extensions, false if not
			*/
			bool HasExtensions() const /* throw (CException) */;

			//! Returns the number of extensions included in this X509CRL. 
			/*!
				\return unsigned int: number of extensions present in the CRL
			*/
			unsigned int GetNumberOfExtensions() const /* throw (CException) */;

			//! Returns an array of all extensions included in this X509CRL.
			/*!
				\return std::vector< clone_ptr<x509::X509Extension> >: vector of extensions present in the CRL
			*/
			std::vector< clone_ptr<x509::X509Extension> > GetExtensions() const /* throw (CException) */;

			//! Returns the extension by object identifier. 
			/*!
				\param const asn1::ObjectID &OID: the object ID of the extension
				\return std::auto_ptr<X509Extension>: the desired extension or null if the requested extension is not present
			*/
			std::auto_ptr<X509Extension> GetExtension(const asn1::ObjectID &OID) const /* throw (CException) */;

			//! Adds the given X509v2 CRL extension.  
			/*!
				\param const X509Extension &ext: the X509v2 CRL extension to add to the list of extensions
			*/
			void AddExtension(const X509Extension &ext);

			//! Removes the extension specified by its object identifier. 
			/*!
				\param const asn1::ObjectID &oid: ObjectID of the extension to be removed from the CRL
				\return bool: true if the extension successfully has been removed false otherwise
			*/
			bool RemoveExtension(const asn1::ObjectID &oid);

			//! Removes all extensions from this CRL. 
			void RemoveAllExtensions();
				
			//! Returns the PEM encoding of this X509CRL. 
			/*!
				\return utils::ByteArray: a byte array containing the PEM encoded CRL bytes
			*/
			utils::ByteArray ToPEM() const /* throw (CException) */;

			//! Writes the DER/PEM encoded form of this X509CRL to disk.
			/*!
				\param szFileName Name of the file on disk.
				\param bPEM Whether to write in PEM format or not? If it is false then DER encoding will be written on the disk. By default its value is false.
				\returns true if this X509CRL is successfully written to disk otherwise throws CException. If an 
				exception is thrown, then the return value is meaningless.
			*/
			bool WriteToDisk(const std::string &szFileName, bool bPEM = false) /* throw (CException) */;

			//! Signs the CRL with the private key of the issuer.
			/*!
				\param const PrivateKey &privateKey: the private key of the issuer
			*/
			void Sign(const PrivateKey &privateKey);
				
			//! Verifies a signed CRL using the given public key.
			/*!
				\param PublicKey &Key: the public key of the CRL issuer
				\return bool: true, if successfully verified, false otherwise
			*/
			bool Verify(PublicKey &Key) /* throw (CException) */;

			//! Verifies a signed CRL using the public key of IssuerCert.
			/*!
				\param const X509Certificate &IssuerCert: X509Certificate of the CRL issuer
				\return bool: true, if successfully verified, false otherwise
			*/
			bool Verify(const X509Certificate &IssuerCert) /* throw (CException) */;

			//! Equality operator. 
			/*!
				\param const X509CRL &rhs: CRL to compare with
				\return bool: true, if this CRL is equal to the CRL in parameters
			*/
			bool operator==(const X509CRL &rhs);

			//! InEquality operator. 
			/*!
				\param const X509CRL &rhs: CRL to compare with
				\return bool: true, if this CRL is not equal to the CRL in the parameters
			*/
			bool operator!=(const X509CRL &rhs);

		private:
			bool IsDER(const unsigned char *pbArray);
			void Construct(const unsigned char *pbArray, unsigned int cLength);

			X509_CRL *m_pCRL;
		};
	}
}

#endif // !PKIBOX_X509_X509CRL_H

