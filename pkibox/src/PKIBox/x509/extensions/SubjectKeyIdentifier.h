
#ifndef PKIBOX_X509_EXTENSIONS_SUBJECT_KEY_IDENTIFIER_H
#define PKIBOX_X509_EXTENSIONS_SUBJECT_KEY_IDENTIFIER_H

#include "../X509Extension.h"

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

	namespace x509
	{
		// Forward declarations
		class PublicKey;

		namespace extensions
		{
			//! This class represents the SubjectKeyIdentifier extension.
			/*! 
				ASN.1 definition of SubjectKeyIdentifier is

				SubjectKeyIdentifier ::= KeyIdentifier

				KeyIdentifier ::= OCTET STRING
			*/
			class SubjectKeyIdentifier : public x509::X509Extension
			{
			public:
				//! Default constructor. Creates an empty SubjectKeyIdentifier object.
				SubjectKeyIdentifier(void);

				virtual ~SubjectKeyIdentifier(void);

				//! Creates a SubjectKeyIdentifier extension with a defined identifier. 
				/*!
					\param const utils::ByteArray &identifier: the subject key identifier as byte array
				*/
				explicit SubjectKeyIdentifier(const utils::ByteArray &identifier);

				//! Creates a SubjectKeyIdentifier extension from the given public key. 
				/*!
					\param const x509::PublicKey &publicKey: the public key for which an identifier shall be created; the encoding of the key must give a X.509 PublicKeyInfo 
				*/
				explicit SubjectKeyIdentifier(const x509::PublicKey &publicKey);

				//! Returns the identifier of this extension. 
				/*!
					\return utils::ByteArray: the identifier, as byte array
				*/
				utils::ByteArray Get()const /* throw (CException)*/;

				//! Returns the object ID of this SubjectKeyIdentifier extension 
				/*!
					\return asn1::ObjectID: the object ID
				*/
				asn1::ObjectID GetObjectID()const /* throw (CException)*/;

				//! Sets the identifier of this SubjectKeyIdentifier extension.  
				/*!
					\param const utils::ByteArray &identifier: a identifier as byte array
				*/
				void Set(const utils::ByteArray &identifier) /* throw (CException)*/;
			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_SUBJECT_KEY_IDENTIFIER_H
