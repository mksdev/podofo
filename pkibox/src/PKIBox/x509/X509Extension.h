
#ifndef PKIBOX_X509_X509_EXTENSION_H
#define PKIBOX_X509_X509_EXTENSION_H

typedef struct X509_extension_st X509_EXTENSION;

namespace PKIBox
{
	namespace utils
	{
		class ByteArray;
	}

	namespace asn1
	{
		class ObjectID;
	}

	namespace pkcs6
	{
		class CExtendedCertificate;
	}

	namespace ocsp
	{
		class CRequest;
		class COCSPRequest;
		class CBasicOCSPResponse;
		class CSingleResponse;
		namespace extensions
		{
			class CServiceLocator;
		}
	}

	namespace tsa
	{
		class CTSTInfo;
	}

	namespace x509
	{
		namespace attr
		{
			class CAttributeCertificate;
		}

		//! This class is the basic implementation for X.509v3 certificate and X.509v2 CRL extensions. Every class, which implements an extension must be derived from this class. 
		/*!
			The ASN.1 syntax of Extension is:

			Extension  ::=  SEQUENCE  {<br>
				extnID      OBJECT IDENTIFIER,<br>
				critical    BOOLEAN DEFAULT FALSE,<br>
				extnValue   OCTET STRING  }<br>

			An extension may be a defined standard extension (e.g. certificatePolicies, keyUsage, ...), 
			or it may be a private extension providing some community-specific information.
		*/
		class X509Extension  
		{
			friend class X509Certificate;
			friend class X509CRLEntry;
			friend class X509CRL;
			friend class ocsp::CRequest;
			friend class ocsp::COCSPRequest;
			friend class ocsp::CBasicOCSPResponse;
			friend class ocsp::CSingleResponse;
			friend class ocsp::extensions::CServiceLocator;
			friend class tsa::CTSTInfo;
			friend class pkcs6::CExtendedCertificate;
			friend class x509::attr::CAttributeCertificate;

		public:
			//! Default constructor. Initializes m_pCertExtension to NULL.
			X509Extension();

			virtual ~X509Extension();

			//! Copy constructor.
			/*!
				\param const X509Extension &rhs
			*/
			X509Extension(const X509Extension &rhs);

			//! Copy assignment operator.
			/*!
				\param const X509Extension &rhs
				\return X509Extension &
			*/
			X509Extension &operator=(const X509Extension &rhs);

			//! Returns true, if this extension is critical. 
			/*!
				\return bool: true, if this extension is marked critical, false otherwise
			*/
			virtual bool IsCritical() const;

			//! Returns the Object Identifier of this X509Extension.
			/*!
				\return asn1::ObjectID: the object ID from the extension this class implements
			*/
			virtual asn1::ObjectID GetOID();

			//! Returns the value of this X509Extension.
			/*!
				\return utils::ByteArray: a byte array containing the value for the extension
			*/
			virtual utils::ByteArray GetValue() const;

			//! Set the extension object identifier
			/*!
				\param const asn1::ObjectID  &obj: the object ID for the extension this class implements
			*/
			virtual void SetOID(const asn1::ObjectID  &obj );

			//! Set the extension's critical flag true/false
			/*!
				\param bool: true if the extension is critical, false if not
			*/
			virtual void SetCritical( bool bCritical );

			//! Set the extension's value
			/*!
				\param const utils::ByteArray &baValue: a byte array containing the value for the extension
			*/
			virtual void SetValue(const utils::ByteArray &baValue);

		protected:
			X509_EXTENSION *m_pCertExtension;	// Pointer to underlying OpenSSL struct.
		};
	}
}

#endif // !PKIBOX_X509_X509_EXTENSION_H
