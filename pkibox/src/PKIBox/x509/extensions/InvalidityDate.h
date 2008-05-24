
#ifndef PKIBOX_X509_EXTENSION_INVALIDITY_DATE_H
#define PKIBOX_X509_EXTENSION_INVALIDITY_DATE_H

#include "../X509Extension.h"

namespace PKIBox
{
	namespace utils
	{
		class DateTime;
	}

	namespace x509
	{
		namespace extensions
		{
			//! This class implements the InvalidityDate extension.
			/*!
				The object identifier for the CRLNumber extension is defined as: 

				id-ce-cRLReason OBJECT IDENTIFIER ::= { id-ce 24 } 

				which corresponds to the OID string "2.5.29.24". 

				ASN.1 definition of InvalidityDate is:

				invalidityDate ::= GeneralizedTime
			*/
			class InvalidityDate : public x509::X509Extension
			{
			public:
				//! Default constructor.
				InvalidityDate(void);

				virtual ~InvalidityDate(void);

				//! Creates a new InvalidityDate from the given date. 
				/*!
					\param const utils::DateTime &invalidityDate: the invalidity date to be set
				*/
				explicit InvalidityDate(const utils::DateTime &invalidityDate);
					
				//! Returns the invalidity date. 
				/*!
					\return utils::DateTime: the invalidity date
				*/
				utils::DateTime GetInvalidityDate() const;

				//! Sets the invality date of this InvalidityDate object.  
				/*!
					\param const utils::DateTime &invalidityDate: the invalidity date to be set
				*/
				void SetInvalidityDate(const utils::DateTime &invalidityDate);
			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSION_INVALIDITY_DATE_H

