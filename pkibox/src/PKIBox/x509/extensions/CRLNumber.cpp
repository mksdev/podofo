
#include "CRLNumber.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "../../NullPointerException.h"
#include "../../utils/BigInteger.h"

using namespace std;

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
			CRLNumber::CRLNumber(void)
			{

			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			CRLNumber::~CRLNumber(void)
			{
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			CRLNumber::CRLNumber(const utils::BigInteger &crlNumber)
			{
				ASN1_INTEGER *pCRLNumber = ::BN_to_ASN1_INTEGER(crlNumber.m_pBN, NULL);
				if(!pCRLNumber)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pCertExtension = ::X509V3_EXT_i2d(NID_crl_number, 0, pCRLNumber);
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
			utils::BigInteger CRLNumber::GetCRLNumber() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no CRLNumber to get CRLNumber from.");

				ASN1_INTEGER *pCRLNumber = (ASN1_INTEGER *) ::X509V3_EXT_d2i(m_pCertExtension);
				if(!pCRLNumber)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				utils::BigInteger CRLNumber;
				CRLNumber.m_pBN = ::ASN1_INTEGER_to_BN(pCRLNumber, NULL);
				
				::ASN1_INTEGER_free(pCRLNumber);
				return CRLNumber; 
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			void CRLNumber::SetCRLNumber(const utils::BigInteger &crlNumber)
			{
				ASN1_INTEGER *pCRLNumber = ::BN_to_ASN1_INTEGER(crlNumber.m_pBN, NULL);
				if(!pCRLNumber)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				X509_EXTENSION *pCertExtension = ::X509V3_EXT_i2d(NID_crl_number, 0, pCRLNumber);
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

