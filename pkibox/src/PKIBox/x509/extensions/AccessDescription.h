
#ifndef PKIBOX_X509_EXTENSIONS_ACCESS_DESCRIPTION_H
#define PKIBOX_X509_EXTENSIONS_ACCESS_DESCRIPTION_H

typedef struct ACCESS_DESCRIPTION_st ACCESS_DESCRIPTION;

#include <memory>

namespace PKIBox
{
	namespace asn1
	{
		class ObjectID;
		class GeneralName;
	}

	namespace x509
	{
		namespace extensions
		{
			//! This class represents the ASN.1 type AccessDescription used in Authority Information Access extension.
			/*!
				AccessDescription  ::=  SEQUENCE {<br>
					accessMethod          OBJECT IDENTIFIER,<br>
					accessLocation        GeneralName  }<br>
			*/
			class AccessDescription
			{
				friend class CX509Certificate;
				friend class AuthorityInformationAccess;

			public:
				//! Default constructor. Initializes m_pAccessDesc to NULL.
				AccessDescription(void);

				//! Constructs an AccessDescription from an AccessMethod and AccessLocation.
				/*!
					\param const asn1::ObjectID &Method: the accessMethod OID
					\param const asn1::GeneralName &Location: the accessLocation GeneralName
				*/
				AccessDescription(const asn1::ObjectID &Method, const asn1::GeneralName &Location);

				virtual ~AccessDescription(void);

				//! Copy constructor.
				/*!
					\param const AccessDescription &rhs
				*/
				AccessDescription(const AccessDescription &rhs);

				//! Copy assignment operator.
				/*!
					\param const AccessDescription &rhs
					\return AccessDescription &
				*/
				AccessDescription &operator=(const AccessDescription &rhs);

				//! Returns the access method Object Identifier. 
				/*!
					\return asn1::ObjectID: the access method OID or null if not set
				*/
				asn1::ObjectID GetAccessMethod() const;

				//! Sets the access method Object Identifier. 
				/*!
					\param const asn1::ObjectID &Method: the access method OID
				*/
				void SetAccessMethod(const asn1::ObjectID &Method);

				//! Returns the access location.
				/*!
					\return std::auto_ptr<asn1::GeneralName>: the access location as GeneralName or null if not set
				*/
				std::auto_ptr<asn1::GeneralName> GetAccessLocation() const;

				//! Sets the access location.
				/*!
					\param const asn1::GeneralName &Location: the access location as GeneralName
				*/
				void SetAccessLocation(const asn1::GeneralName &Location);

			private:
				ACCESS_DESCRIPTION *m_pAccessDesc; // Pointer to underlying OpenSSL AccessDescription structure.

			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSIONS_ACCESS_DESCRIPTION_H
