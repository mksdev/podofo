
#include "DeltaCRLIndicator.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../Exception.h"
#include "../../NullPointerException.h"
#include "../../utils/BigInteger.h"

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			DeltaCRLIndicator::DeltaCRLIndicator(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			DeltaCRLIndicator::~DeltaCRLIndicator(void)
			{
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			DeltaCRLIndicator::DeltaCRLIndicator(const utils::BigInteger &baseCRLNumber) 
			{
				ASN1_INTEGER *pCRLNumber = ::BN_to_ASN1_INTEGER(baseCRLNumber.m_pBN, NULL);
				if(!pCRLNumber)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pCertExtension = ::X509V3_EXT_i2d(NID_delta_crl, 1, pCRLNumber); // This extension is critical.
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::ASN1_INTEGER_free(pCRLNumber);
					throw Exception(pc);
				}

				::ASN1_INTEGER_free(pCRLNumber);
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			utils::BigInteger DeltaCRLIndicator::GetBaseCRLNumber() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no DeltaCRLIndicator to get BaseCRLNumber from.");

				ASN1_INTEGER *pBaseCRLNumber = (ASN1_INTEGER *) ::X509V3_EXT_d2i(m_pCertExtension);
				if(!pBaseCRLNumber)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				utils::BigInteger baseCRLNumber;
				baseCRLNumber.m_pBN = ::ASN1_INTEGER_to_BN(pBaseCRLNumber, NULL);

				if(pBaseCRLNumber)
					::ASN1_INTEGER_free(pBaseCRLNumber);

				return baseCRLNumber;
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			void DeltaCRLIndicator::SetBaseCRLNumber(const utils::BigInteger &baseCRLNumber)
			{
				ASN1_INTEGER *pCRLNumber = ::BN_to_ASN1_INTEGER(baseCRLNumber.m_pBN, NULL);
				if(!pCRLNumber)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				X509_EXTENSION *pCertExtension = ::X509V3_EXT_i2d(NID_delta_crl, 1, pCRLNumber); // This extension is critical.
				if(!pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::ASN1_INTEGER_free(pCRLNumber);
					throw Exception(pc);
				}

				::ASN1_INTEGER_free(pCRLNumber);

				if(m_pCertExtension)
					::X509_EXTENSION_free(m_pCertExtension);

				m_pCertExtension = pCertExtension;
			}

		}
	}
}


