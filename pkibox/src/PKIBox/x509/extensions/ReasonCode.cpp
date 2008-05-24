
#include "ReasonCode.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../../Exception.h"
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
			ReasonCode::ReasonCode(void)
			{

			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			ReasonCode::ReasonCode(int iReasonCode)
			{
				ASN1_ENUMERATED *pEnumerated = ::ASN1_ENUMERATED_new();
				int iRet = ::ASN1_ENUMERATED_set(pEnumerated, iReasonCode);

				int iSize = ::i2d_ASN1_ENUMERATED(pEnumerated, NULL);
				if(iSize == -1)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					::ASN1_ENUMERATED_free(pEnumerated);

					throw Exception(pc);
				}

				unsigned char *pEncoded = (unsigned char *) ::malloc(iSize); // Allocate
				iSize = ::i2d_ASN1_ENUMERATED(pEnumerated, &pEncoded);
				pEncoded -= iSize;

				ASN1_OCTET_STRING *pOctetString = ::ASN1_OCTET_STRING_new();
				iRet = ::ASN1_OCTET_STRING_set(pOctetString, pEncoded, iSize);

				m_pCertExtension = ::X509_EXTENSION_create_by_NID(NULL, NID_crl_reason, 0, pOctetString);
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					if(pEncoded)
						::free(pEncoded);  // Deallocate

					::ASN1_ENUMERATED_free(pEnumerated);
					::ASN1_OCTET_STRING_free(pOctetString);

					throw Exception(pc);
				}

				if(pEncoded)
					::free(pEncoded);  // Deallocate

				::ASN1_ENUMERATED_free(pEnumerated);
				::ASN1_OCTET_STRING_free(pOctetString);
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			ReasonCode::~ReasonCode(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			ReasonCode::REASON_CODE ReasonCode::GetReasonCode() const
			{
				if(m_pCertExtension)
				{
					ASN1_ENUMERATED *pReasonCode = (ASN1_ENUMERATED *) ::X509V3_EXT_d2i(m_pCertExtension);
					if(!pReasonCode)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}

					long l = ::ASN1_ENUMERATED_get(pReasonCode);

					if(pReasonCode)
						::ASN1_ENUMERATED_free(pReasonCode);

					switch(l)
					{
					case 0:
						return ReasonCode::unspecified;
					case 1:
						return ReasonCode::keyCompromise;
					case 2:
						return ReasonCode::cACompromise;
					case 3:
						return ReasonCode::affiliationChanged;
					case 4:
						return ReasonCode::superseded;
					case 5:
						return ReasonCode::cessationOfOperation;
					case 6:
						return ReasonCode::certificateHold;
					case 8:
						return ReasonCode::removeFromCRL;
					case 9:
						return ReasonCode::privilegeWithdrawn;
					case 10:
						return ReasonCode::aACompromise;

					default:
						return ReasonCode::unspecified;
					}
				}
				else
					throw Exception("There is no ReasonCode to get ReasonCode from.");
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			string ReasonCode::GetReasonCodeString() const
			{
				if(m_pCertExtension)
				{
					ASN1_ENUMERATED *pReasonCode = (ASN1_ENUMERATED *) ::X509V3_EXT_d2i(m_pCertExtension);
					if(!pReasonCode)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}

					long l = ::ASN1_ENUMERATED_get(pReasonCode);

					if(pReasonCode)
						::ASN1_ENUMERATED_free(pReasonCode);

					switch(l)
					{
					case 0:
						return "unspecified";
					case 1:
						return "keyCompromise";
					case 2:
						return "cACompromise";
					case 3:
						return "affiliationChanged";
					case 4:
						return "superseded";
					case 5:
						return "cessationOfOperation";
					case 6:
						return "certificateHold";
					case 8:
						return "removeFromCRL";
					case 9:
						return "privilegeWithdrawn";
					case 10:
						return "aACompromise";

					default:
						return "unspecified";
					}
				}
				else
					throw Exception("There is no ReasonCode to get ReasonCode from.");
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			void ReasonCode::SetReasonCode(const REASON_CODE reasonCode)
			{
				long l = -1;
				switch(reasonCode)
				{
				case unspecified:
					l = 0;	break;
				case keyCompromise:
					l = 1;	break;
				case cACompromise:
					l = 2;	break;
				case affiliationChanged:
					l = 3;	break;
				case superseded:
					l = 4;	break;
				case cessationOfOperation:
					l = 5;	break;
				case certificateHold:
					l = 6;	break;
				case removeFromCRL:
					l = 8;	break;
				case privilegeWithdrawn:
					l = 9;	break;
				case aACompromise:
					l = 10;	break;
				default:
					l = 0;	break;
				}

				ASN1_ENUMERATED *pReasonCode = ::ASN1_ENUMERATED_new();
				if(!pReasonCode)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				::ASN1_ENUMERATED_set(pReasonCode, l);

				X509_EXTENSION *pCertExtension = ::X509V3_EXT_i2d(NID_crl_reason, 0, pReasonCode);
				if(!pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::ASN1_ENUMERATED_free(pReasonCode);
					throw Exception(pc);
				}

				::ASN1_ENUMERATED_free(pReasonCode);

				if(m_pCertExtension)
					::X509_EXTENSION_free(m_pCertExtension);

				m_pCertExtension = pCertExtension;
			}
		}
	}
}

