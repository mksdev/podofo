
#ifndef PKIBOX_X509_EXTENSION_CRL_NUMBER_H
#define PKIBOX_X509_EXTENSION_CRL_NUMBER_H

#include <string>
#include "../X509Extension.h"

namespace PKIBox
{
	namespace utils
	{
		class BigInteger;
	}

	namespace x509
	{
		namespace extensions
		{
			//! This class implements the CRLNumber extension. 
			/*!
				The object identifier for the CRLNumber extension is defined as: 

				id-ce-cRLNumber OBJECT IDENTIFIER ::= { id-ce 20 } 

				which corresponds to the OID string "2.5.29.20". 

				ASN.1 definition of CRLNumber extension is: 

				cRLNumber ::= INTEGER (0..MAX)
			*/
			class CRLNumber : public x509::X509Extension
			{
			public:
				//! Default constructor.
				CRLNumber(void);

				virtual ~CRLNumber(void);

				//! Creates a new CRLNumber from a BigInteger. 
				/*!
					\param const utils::BigInteger &crlNumber: the CRL number
				*/
				explicit CRLNumber(const utils::BigInteger &crlNumber);
					
				//! Returns the CRL number as long. 
				/*!
					\return utils::BigInteger: the CRL number
				*/
				utils::BigInteger GetCRLNumber() const;

				//! Sets the CRL number. 
				/*!
					\param const utils::BigInteger &crlNumber: the CRL number
				*/
				void SetCRLNumber(const utils::BigInteger &crlNumber);
			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSION_CRL_NUMBER_H
