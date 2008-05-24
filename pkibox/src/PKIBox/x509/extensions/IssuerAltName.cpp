
#include "IssuerAltName.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../Exception.h"
#include "../../NullPointerException.h"
#include "../../asn1/GeneralName.h"

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
			IssuerAltName::IssuerAltName(void)
			{
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			IssuerAltName::~IssuerAltName(void)
			{
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			IssuerAltName::IssuerAltName(const std::vector<asn1::GeneralName> &vecGeneralNames)
			{
				GENERAL_NAMES *pIssuerAltName = ::GENERAL_NAMES_new();
				if(!pIssuerAltName)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				for( unsigned int i=0; i<vecGeneralNames.size(); ++i )
				{
					sk_GENERAL_NAME_push( pIssuerAltName, GENERAL_NAME_dup( vecGeneralNames[i].m_pName ) );
				}

				m_pCertExtension = ::X509V3_EXT_i2d( NID_issuer_alt_name, 0, pIssuerAltName );
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::GENERAL_NAMES_free(pIssuerAltName);
					throw Exception(pc);
				}

				::GENERAL_NAMES_free(pIssuerAltName);
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			std::vector<asn1::GeneralName> IssuerAltName::GetGeneralNames()const /* throw (Exception)*/
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no IssuerAltName to get GeneralNames from.");

				GENERAL_NAMES *pIssuerAltName = (GENERAL_NAMES *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pIssuerAltName)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				int nGNCount = sk_GENERAL_NAME_num( pIssuerAltName );

				std::vector<asn1::GeneralName> vecGeneralNames;
				for( int iCount=0 ; iCount<nGNCount ; iCount++ )
				{
					asn1::GeneralName GN;
					GN.m_pName = ::GENERAL_NAME_dup( sk_GENERAL_NAME_value( pIssuerAltName, iCount ) );
					vecGeneralNames.push_back(GN);
				}

				if(pIssuerAltName)
					::GENERAL_NAMES_free(pIssuerAltName);

				return vecGeneralNames;
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			void IssuerAltName::SetGeneralNames(const std::vector<asn1::GeneralName> &vecGeneralNames) /* throw (Exception)*/
			{
				GENERAL_NAMES *pIssuerAltName = ::GENERAL_NAMES_new();
				if(!pIssuerAltName)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				for( unsigned int i=0; i<vecGeneralNames.size(); ++i)
				{
					sk_GENERAL_NAME_push( pIssuerAltName, ::GENERAL_NAME_dup( vecGeneralNames[i].m_pName ) );
				}

				X509_EXTENSION *pCertExtension = ::X509V3_EXT_i2d( NID_issuer_alt_name, 0, pIssuerAltName );
				if(!pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::GENERAL_NAMES_free(pIssuerAltName);
					throw Exception(pc);
				}

				::GENERAL_NAMES_free(pIssuerAltName);

				if(m_pCertExtension)
					::X509_EXTENSION_free(m_pCertExtension);

				m_pCertExtension = pCertExtension;
			}
		}
	}
}


