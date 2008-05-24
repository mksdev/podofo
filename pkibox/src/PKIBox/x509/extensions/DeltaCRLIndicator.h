
#ifndef PKIBOX_X509_EXTENSIONS_DELTA_CRL_INDICATOR_H
#define PKIBOX_X509_EXTENSIONS_DELTA_CRL_INDICATOR_H

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
			//! This class implements the DeltaCRLIndicator extension. 
			/*!
				The DeltaCRLIndicator extension is a critical standard X509v2 CRL extension. 
				The ASN.1 definition for DeltaCRLIndicator is: 

				deltaCRLIndicator ::= BaseCRLNumber

				BaseCRLNumber ::= CRLNumber

				cRLNumber ::= INTEGER (0..MAX)
			*/
			class DeltaCRLIndicator : public x509::X509Extension
			{
			public:
				//! Default constructor.
				DeltaCRLIndicator(void);

				virtual ~DeltaCRLIndicator(void);

				//! Creates a new DeltaCRLIndicator from a BigInteger base crl number. 
				/*!
					\param const utils::BigInteger &baseCRLNumber: the base crl number
				*/
				explicit DeltaCRLIndicator(const utils::BigInteger &baseCRLNumber);

				//! Returns the base crl number as BigInteger. 
				/*!
					\return utils::BigInteger: the base crl number
				*/
				utils::BigInteger GetBaseCRLNumber() const;

				//! Sets the base crl number. 
				/*!
					\param const utils::BigInteger &baseCRLNumber: the base crl number
				*/
				void SetBaseCRLNumber(const utils::BigInteger &baseCRLNumber);
			};			
		}
	}
}

#endif // !PKIBOX_X509_EXTENSIONS_DELTA_CRL_INDICATOR_H

