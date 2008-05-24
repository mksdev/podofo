
#ifndef PKIBOX_X509_EXTENSIONS_EXTENDED_KEY_USAGE_H
#define PKIBOX_X509_EXTENSIONS_EXTENDED_KEY_USAGE_H

#include <memory>
#include <vector>
#include "../X509Extension.h"


namespace PKIBox
{
	namespace asn1
	{
		class ObjectID;
	}

	namespace x509
	{
		namespace extensions
		{
			//! This class represents the ExtendedKeyUsage extension.
			/*!
				The ASN.1 definition of ExtendedKeyUsage extension is

				ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId

				KeyPurposeId ::= OBJECT IDENTIFIER

				The following extended key usage purposes are defined by RFC 2459: 

				serverAuth (1.3.6.1.5.5.7.3.1) -- TLS Web server authentication <br>
				clientAuth (1.3.6.1.5.5.7.3.2) -- TLS Web client authentication <br>
				codeSigning (1.3.6.1.5.5.7.3.3) -- Code signing <br>
				emailProtection (1.3.6.1.5.5.7.3.4) -- E-mail protection <br>
				timeStamping (1.3.6.1.5.5.7.3.8) -- Timestamping <br>
				ocspSigning (1.3.6.1.5.5.7.3.9) -- OCSPstamping <br>
			*/
			class ExtendedKeyUsage : public x509::X509Extension
			{
			public:
				//! Default constructor. Creates an empty ExtendedKeyUsage.
				ExtendedKeyUsage(void);

				virtual ~ExtendedKeyUsage(void);

				//! Returns a KeyPurposeID specified by index.
				/*!
					\param unsigned int index: index of key purpose id to get
					\return std::auto_ptr<asn1::ObjectID>: Key purpose id at desired position
				*/
				std::auto_ptr<asn1::ObjectID> GetKeyPurposeID(unsigned int index) const; 

				//! Inserts a KeyPurposeID specified by OID.
				/*!
					\param const asn1::ObjectID &OID: the KeyPurposeID to add
				*/
				void AddKeyPurposeID(const asn1::ObjectID &OID) /* throw (Exception)*/;

				//! Remove the KeyPurposeID specified by OID.
				/*!
					\param const asn1::ObjectID &OID: the KeyPurposeID to remove
				*/
				void RemoveKeyPurposeID(const asn1::ObjectID &OID) /* throw (Exception)*/;

				//! Removes all the KeyPurposeID from this extension.
				void RemoveAllKeyPurposeIDs() /* throw (Exception)*/;

				//! Returns total number of KeyPurposeIDs in this ExtendedKeyUsage extension.
				/*!
					\return unsigned int: number of key purpose ids present
				*/
				unsigned int GetNumberofKeyPurposeIDs() const; 

				//! Returns all KeyPurposeIDs included in this extension.
				/*!
					\return std::vector<asn1::ObjectID>: vector of key purpose ids present
				*/
				std::vector<asn1::ObjectID> GetKeyPurposeIDs() const;

				//! Checks whether a specific KeyPurposeID present in this Extended Key usage extension.
				/*!
					\param const asn1::ObjectID &oid: key purpose id to look for
					\return bool: true if specific key purpose id is present, false otherwise
				*/
				bool IsKeyPurposeID(const asn1::ObjectID &oid) const;

			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_EXTENDEDKEYUSAGE_H

