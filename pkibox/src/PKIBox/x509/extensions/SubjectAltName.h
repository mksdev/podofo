
#ifndef PKIBOX_X509_EXTENSIONS_SUBJECT_ALT_NAME_H
#define PKIBOX_X509_EXTENSIONS_SUBJECT_ALT_NAME_H

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
			//! This class represents SubjectAltName extension.
			/*!
				ASN1 Definition of SubjectAltName is:

				SubjectAltName ::= GeneralNames
			*/
			class SubjectAltName : public x509::X509Extension
			{
			public:
				//! Default constructor. Creates an empty object of SubjectAltName.
				SubjectAltName(void);

				virtual ~SubjectAltName(void);

				//! Constructs a SubjectAltName extension with the given GeneralNames as value.
				/*!
					\param const std::vector<asn1::GeneralName> &vecGeneralNames: the alternative name of the subject as vector of GeneralName
				*/
				explicit SubjectAltName(const std::vector<asn1::GeneralName> &vecGeneralNames);

				//! Returns the alternative name of the subject. 
				/*!
					\return std::vector<asn1::GeneralName>: the alternative name as vector of GeneralName
				*/
				std::vector<asn1::GeneralName> GetGeneralNames()const /* throw (CException)*/;

				//! Sets the alternative name of the subject.
				/*!
					\param const std::vector<asn1::GeneralName> &vecGeneralNames: the alternative name as vector of GeneralName
				*/
				void SetGeneralNames(const std::vector<asn1::GeneralName> &vecGeneralNames) /* throw (CException)*/;		
			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSIONS_SUBJECT_ALT_NAME_H


