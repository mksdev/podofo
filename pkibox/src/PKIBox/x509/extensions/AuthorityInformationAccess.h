
#ifndef PKIBOX_X509_EXTENSIONS_AUTHORITY_INFORMATION_ACCESS_H
#define PKIBOX_X509_EXTENSIONS_AUTHORITY_INFORMATION_ACCESS_H

#include <memory>
#include <vector>
#include "../X509Extension.h"

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			class AccessDescription;

			//! This class represents the extension AuthorityInformationAccess.
			/*! 
				The ASN.1 definition of AuthorityInformationAccess is

				AuthorityInfoAccessSyntax  ::=<br>
				SEQUENCE SIZE (1..MAX) OF AccessDescription<br>

				AccessDescription  ::=  SEQUENCE {<br>
					accessMethod          OBJECT IDENTIFIER,<br>
					accessLocation        GeneralName  }<br>
			*/
			class AuthorityInformationAccess : public x509::X509Extension
			{
			public:
				//! Default constructor. Creates an empty AuthorityInformationAccess.
				AuthorityInformationAccess(void);

				virtual ~AuthorityInformationAccess(void);

				//! Returns the number of AccessDescription objects contained in this AuthorityInformationAccess.
				/*!
					\return unsigned int: Number of access descriptions present
				*/
				unsigned int GetNumberofAccessDescriptions() const;

				//! Returns a collection of AccessDescriptions contained in this AuthorityInformationAccess.
				/*!
					\return std::vector<AccessDescription>: an vector of the access descriptions
				*/
				std::vector<AccessDescription> GetAccessDescriptions() const;

				//! Returns an AccessDescription specified by index.
				/*!
					\param unsigned int n: access description at location n
					\return std::auto_ptr<AccessDescription>: desired access description at n
				*/
				std::auto_ptr<AccessDescription> GetAccessDescription(unsigned int n) const;

				//! Adds an AccessDescription to this AuthorityInformationAccess. 
				/*!
					\param const AccessDescription &Info: the access description to add
				*/
				void AddAccessDescription(const AccessDescription &Info);

			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_AUTHORITY_INFORMATION_ACCESS_H
