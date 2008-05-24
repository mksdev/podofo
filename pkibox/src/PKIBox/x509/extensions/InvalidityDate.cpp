
#include "InvalidityDate.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "../../utils/DateTime.h"


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
			InvalidityDate::InvalidityDate(void)
			{

			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			InvalidityDate::~InvalidityDate(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			InvalidityDate::InvalidityDate(const utils::DateTime &invalidityDate)
			{
				// Create a GENERALIZED_TIME from invalidityDate.
				ASN1_GENERALIZEDTIME *pinvalidityDate = ASN1_GENERALIZEDTIME_set(NULL, invalidityDate.GetTime());

				// Get GENERALIZED_TIME in DER format.
				int iSize = ::i2d_ASN1_GENERALIZEDTIME(pinvalidityDate, NULL);
				if(iSize == -1)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::ASN1_GENERALIZEDTIME_free(pinvalidityDate);
					throw Exception(pc);
				}

				unsigned char *pEncoded = (unsigned char *) ::malloc(iSize); // Allocate
				iSize = ::i2d_ASN1_GENERALIZEDTIME(pinvalidityDate, &pEncoded);
				pEncoded -= iSize;

				// wrap DER bytes of GENERALIZED_TIME in OCTET_STRING.
				ASN1_OCTET_STRING *pOctetString = ::ASN1_OCTET_STRING_new();
				int iRet = ::ASN1_OCTET_STRING_set(pOctetString, pEncoded, iSize);

				// Use OCTET_STRING to create X509_EXTENSION.
				m_pCertExtension = ::X509_EXTENSION_create_by_NID(NULL, NID_invalidity_date, 0, pOctetString);
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					if(pEncoded)
						::free(pEncoded);  // Deallocate

					::ASN1_GENERALIZEDTIME_free(pinvalidityDate);
					::ASN1_OCTET_STRING_free(pOctetString);

					throw Exception(pc);
				}

				if(pEncoded)
					::free(pEncoded);  // Deallocate

				::ASN1_GENERALIZEDTIME_free(pinvalidityDate);
				::ASN1_OCTET_STRING_free(pOctetString);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			utils::DateTime InvalidityDate::GetInvalidityDate() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no InvalidityDate to get date from.");

				ASN1_GENERALIZEDTIME *pInvalidityDate = (ASN1_GENERALIZEDTIME *) ::X509V3_EXT_d2i(m_pCertExtension);
				if(!pInvalidityDate)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				time_t time = ASN1_GENERALIZEDTIME_get(pInvalidityDate);

				if(pInvalidityDate)
					ASN1_GENERALIZEDTIME_free(pInvalidityDate);

				return utils::DateTime(time);


			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			void InvalidityDate::SetInvalidityDate(const utils::DateTime &invalidityDate)
			{
				ASN1_GENERALIZEDTIME *pInvalidityDate = ::ASN1_GENERALIZEDTIME_set(NULL, invalidityDate.GetTime());
				if(!pInvalidityDate)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				X509_EXTENSION *pCertExtension = ::X509V3_EXT_i2d(NID_invalidity_date, 0, pInvalidityDate);
				if(!pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::ASN1_GENERALIZEDTIME_free(pInvalidityDate);
					throw Exception(pc);
				}

				::ASN1_GENERALIZEDTIME_free(pInvalidityDate);

				if(m_pCertExtension)
					::X509_EXTENSION_free(m_pCertExtension);

				m_pCertExtension = pCertExtension;
			}
		}
	}

}


