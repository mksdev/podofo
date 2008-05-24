
#include "SubjectAltName.h"

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
			// Function name	: SubjectAltName
			// Description	    : Default constructor, creates an empty SubjectAltName object.
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			SubjectAltName::SubjectAltName(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: ~SubjectAltName
			// Description	    : Destructor.
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			SubjectAltName::~SubjectAltName(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: SubjectAltName
			// Description	    : Constructs a SubjectAltName extension with the given GeneralNames as value.
			// Return type		: 
			// Argument         : const std::vector<GeneralName> &vecGeneralNames
			//---------------------------------------------------------------------------------------
			SubjectAltName::SubjectAltName(const std::vector<asn1::GeneralName> &vecGeneralNames)
			{
				GENERAL_NAMES *pSubjectAltName = ::GENERAL_NAMES_new();
				if(!pSubjectAltName)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				for( unsigned int i=0; i<vecGeneralNames.size(); ++i )
				{
					sk_GENERAL_NAME_push( pSubjectAltName, GENERAL_NAME_dup( vecGeneralNames[i].m_pName ) );
				}

				m_pCertExtension = ::X509V3_EXT_i2d( NID_subject_alt_name, 0, pSubjectAltName );
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::GENERAL_NAMES_free(pSubjectAltName);
					throw Exception(pc);
				}

				::GENERAL_NAMES_free(pSubjectAltName);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetGeneralNames
			// Description	    : Returns the alternative name of the subject. 
			// Return type		: std::vector<GeneralName>
			// Argument         : void
			//---------------------------------------------------------------------------------------
			std::vector<asn1::GeneralName> SubjectAltName::GetGeneralNames()const /* throw (Exception)*/
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no SubjectAltName to get GeneralNames from.");

				GENERAL_NAMES *pSubjectAltName = (GENERAL_NAMES *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pSubjectAltName)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				int nGNCount = sk_GENERAL_NAME_num( pSubjectAltName );

				std::vector<asn1::GeneralName> vecGeneralNames;
				for( int iCount=0 ; iCount<nGNCount ; iCount++ )
				{
					asn1::GeneralName GN;
					GN.m_pName = ::GENERAL_NAME_dup( sk_GENERAL_NAME_value( pSubjectAltName, iCount ) );
					vecGeneralNames.push_back(GN);
				}

				if(pSubjectAltName)
					::GENERAL_NAMES_free(pSubjectAltName);

				return vecGeneralNames;
			}

			//---------------------------------------------------------------------------------------
			// Function name	: CSubjectKeyIdentifier
			// Description	    : Sets the alternative name of the subject.  
			// Return type		: void
			// Argument         : const std::vector<GeneralName> &vecGeneralNames
			//---------------------------------------------------------------------------------------
			void SubjectAltName::SetGeneralNames(const std::vector<asn1::GeneralName> &vecGeneralNames) /* throw (Exception)*/
			{
				GENERAL_NAMES *pSubjectAltName = ::GENERAL_NAMES_new();
				if(!pSubjectAltName)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				for( unsigned int i=0; i<vecGeneralNames.size(); ++i)
				{
					sk_GENERAL_NAME_push( pSubjectAltName, ::GENERAL_NAME_dup( vecGeneralNames[i].m_pName ) );
				}

				X509_EXTENSION *pCertExtension = ::X509V3_EXT_i2d( NID_subject_alt_name, 0, pSubjectAltName );
				if(!pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					::GENERAL_NAMES_free(pSubjectAltName);
					throw Exception(pc);
				}

				::GENERAL_NAMES_free(pSubjectAltName);

				if(m_pCertExtension)
					::X509_EXTENSION_free(m_pCertExtension);

				m_pCertExtension = pCertExtension;
			}
		}
	}

}

