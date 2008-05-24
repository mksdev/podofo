
#ifndef PKIBOX_X509_EXTENSIONS_ISSUER_ALT_NAME_H
#define PKIBOX_X509_EXTENSIONS_ISSUER_ALT_NAME_H

#include <vector>
#include "../X509Extension.h"

namespace PKIBox
{
	namespace asn1
	{
		class GeneralName;
	}

	namespace x509
	{
		namespace extensions
		{
			//! This class represents IssuerAltName extension.
			/*!
				ASN1 Definition of IssuerAltName is:

				IssuerAltName ::= GeneralNames
			*/
			class IssuerAltName : public x509::X509Extension
			{
			public:
				//! Default constructor.
				IssuerAltName(void);

				virtual ~IssuerAltName(void);

				//! Constructs a SubjectAltName extension with the given GeneralNames as value.
				/*!
					\param const std::vector<asn1::GeneralName> &vecGeneralNames: the alternative name of the issuer as vector of GeneralName
				*/
				explicit IssuerAltName(const std::vector<asn1::GeneralName> &vecGeneralNames);

				//! Returns the alternative name of the issuer. 
				/*!
					\return std::vector<asn1::GeneralName>: the alternative name as vector of GeneralName
				*/
				std::vector<asn1::GeneralName> GetGeneralNames()const /* throw (CException)*/;

				//! Sets the alternative name of the issuer.  
				/*!
					\param const std::vector<asn1::GeneralName> &vecGeneralNames: alternative name of the issuer as vector of GeneralName
				*/
				void SetGeneralNames(const std::vector<asn1::GeneralName> &vecGeneralNames) /* throw (CException)*/;		
			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSIONS_ISSUER_ALT_NAME_H

