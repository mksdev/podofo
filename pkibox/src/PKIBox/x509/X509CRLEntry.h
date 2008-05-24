
#ifndef PKIBOX_X509_X509_CRL_ENTRY_H
#define PKIBOX_X509_X509_CRL_ENTRY_H

typedef struct X509_revoked_st X509_REVOKED;

#include <memory>
#include <string>
#include <vector>
#include "../utils/clone_ptr.h"

namespace PKIBox
{
	namespace utils
	{
		class DateTime;
		class BigInteger;
	}

	namespace asn1
	{
		class ObjectID;
	}

	namespace x509
	{
		class X509Extension;
		class X509Certificate;

		//! This class represents a revoked entry in a Certificate Revocation List. 
		/*!
			The ASN.1 syntax of X509CRLEntry is

			revokedCertificates    SEQUENCE OF SEQUENCE  {
				userCertificate    CertificateSerialNumber,
				revocationDate     ChoiceOfTime,
				crlEntryExtensions Extensions OPTIONAL -- if present, must be v2 }  OPTIONAL

			CertificateSerialNumber  ::=  INTEGER

			Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

			Extension  ::=  SEQUENCE  {
				extnId        OBJECT IDENTIFIER,
				critical      BOOLEAN DEFAULT FALSE,
				extnValue     OCTET STRING -- contains a DER encoding of a value of the type registered for use with the extnId object identifier value}
		*/
		class X509CRLEntry  
		{
			friend class X509CRL;

		public:
			//! Default constructor. Initializes m_pCRLEntry to NULL.
			X509CRLEntry();

			//! Creates a revoked certificate from a serial number and a date.
			/*!
				\param const utils::BigInteger &serialNumber: serial number of the certificate to be revoked
				\param const utils::DateTime &revocationDate: revocation date
			*/
			X509CRLEntry(const utils::BigInteger &serialNumber, const utils::DateTime &revocationDate);

			//! Creates a revoked certificate from a certificate and a date.
			/*!
				\param const x509::X509Certificate &cert: X509Certificate to be revoked
				\param const utils::DateTime &revocationDate: revocation date
			*/
			X509CRLEntry(const x509::X509Certificate &cert, const utils::DateTime &revocationDate);
				
			virtual ~X509CRLEntry();

			//! Copy constructor.
			/*!
				\param const X509CRLEntry &rhs
			*/
			X509CRLEntry(const X509CRLEntry &rhs);

			//! Copy assignment operator.
			/*!
				\param const X509CRLEntry &rhs
				\return X509CRLEntry &
			*/
			X509CRLEntry &operator=(const X509CRLEntry &rhs);

			//! Returns the revocation date of this X509CRLEntry.
			/*!
				\return utils::DateTime: the revocation date
			*/
			utils::DateTime GetRevocationDate() const;

			//! Returns the serial number of this X509CRLEntry.
			/*!
				\return utils::BigInteger: the serial number
			*/
			utils::BigInteger GetSerialNumber() const; 

			//! Equality operator.
			/*!
				\param const X509CRLEntry &CRLEntry
				\return bool: true, if this CRLEntry is equal to CRLEntry provided in parameters
			*/
			bool operator==(const X509CRLEntry &CRLEntry) const;

			//! Non-equality operator.
			/*!
				\param const X509CRLEntry &CRLEntry
				\return bool: true, if this CRLEntry is not equal to CRLEntry provided in parameters
			*/
			bool operator!=(const X509CRLEntry &CRLEntry) const;

			//! Returns true if this X509CRLEntry has extensions
			/*!
				\return bool: true, if this CRLEntry has extensions
			*/
			bool HasExtensions() const /* throw (CException) */;

			//! Returns the number of extensions present in this X509CRLEntry
			/*!
				\return unsigned int: number of extensions present in this CRLEntry
			*/
			unsigned int GetNumberOfExtensions() const /* throw (CException) */;

			//! Returns an array of all extensions included in this X509CRLEntry. 
			/*!
				\return std::vector< clone_ptr<x509::X509Extension> >: vector containing all the extensions present in this CRLEntry
			*/
			std::vector< clone_ptr<x509::X509Extension> > GetExtensions() const /* throw (CException) */;

			//! Returns the extension by object identifier.
			/*!
				\param const asn1::ObjectID &OID: the object ID of the extension
				\return std::auto_ptr<X509Extension>: the desired extension or null if the requested extension is not present
			*/
			std::auto_ptr<X509Extension> GetExtension(const asn1::ObjectID &OID) const /* throw (CException) */;

			//! Adds the given extension to this revoked certificate.  
			/*!
				\param const X509Extension &ext: the X509v2 CRL extension to add to the list of extensions
			*/
			void AddExtension(const X509Extension &ext);

			//! Removes the extension specified by its object identifier. 
			/*!
				\param const asn1::ObjectID &oid: the object ID of the extension to remove
				\return bool: true if the extension successfully has been removed false otherwise
			*/
			bool RemoveExtension(const asn1::ObjectID &oid);

			//! Removes all extensions from this revoked certificate. 
			void RemoveAllExtensions();
				
		private:
			X509_REVOKED *m_pCRLEntry;	// Underlying OpenSSL pointer to CRLEntry data structure.

		};
	}
}

#endif // !PKIBOX_X509_X509_CRL_ENTRY_H

