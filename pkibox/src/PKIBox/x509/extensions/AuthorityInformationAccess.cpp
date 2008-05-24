
#include "AuthorityInformationAccess.h"


// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "AccessDescription.h"

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
			AuthorityInformationAccess::AuthorityInformationAccess(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			AuthorityInformationAccess::~AuthorityInformationAccess(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			unsigned int AuthorityInformationAccess::GetNumberofAccessDescriptions() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no AuthorityInformationAccess to get number of AccessDescriptions from.");

				AUTHORITY_INFO_ACCESS *pAuthInfoAccess = (AUTHORITY_INFO_ACCESS *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pAuthInfoAccess)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				int cAccessDescription = ::sk_num(pAuthInfoAccess);

				if(pAuthInfoAccess)
					::AUTHORITY_INFO_ACCESS_free(pAuthInfoAccess);

				return cAccessDescription;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			vector<AccessDescription> AuthorityInformationAccess::GetAccessDescriptions() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no AuthorityInformationAccess to get AccessDescriptions from.");

				AUTHORITY_INFO_ACCESS *pAuthInfoAccess = (AUTHORITY_INFO_ACCESS *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pAuthInfoAccess)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				vector<AccessDescription> vAccessDescs;
				vAccessDescs.reserve(2);

				int cAIAs = ::sk_num(pAuthInfoAccess);
				for(int i=0; i<cAIAs; ++i)
				{
					AccessDescription AccessDesc;
					AccessDesc.m_pAccessDesc = ACCESS_DESCRIPTION_dup( (ACCESS_DESCRIPTION *)sk_value(pAuthInfoAccess, i) );
					vAccessDescs.push_back(AccessDesc);
				}

				if(pAuthInfoAccess)
					::AUTHORITY_INFO_ACCESS_free(pAuthInfoAccess);

				return vAccessDescs;

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			auto_ptr<AccessDescription> AuthorityInformationAccess::GetAccessDescription(unsigned int n) const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no AuthorityInformationAccess to get AccessDescriptions from.");

				AUTHORITY_INFO_ACCESS *pAuthInfoAccess = (AUTHORITY_INFO_ACCESS *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pAuthInfoAccess)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				ACCESS_DESCRIPTION *pAccessDesc = (ACCESS_DESCRIPTION *)::sk_value(pAuthInfoAccess, n);
				if(pAccessDesc)
				{
					auto_ptr<AccessDescription> p(new AccessDescription);
					p->m_pAccessDesc = ACCESS_DESCRIPTION_dup(pAccessDesc);

					if(pAuthInfoAccess)
						AUTHORITY_INFO_ACCESS_free(pAuthInfoAccess);

					return p;
				}
				else
				{
					if(pAuthInfoAccess)
						AUTHORITY_INFO_ACCESS_free(pAuthInfoAccess);

					return auto_ptr<AccessDescription>(NULL);
				}

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			void AuthorityInformationAccess::AddAccessDescription(const AccessDescription &Info)
			{
				if(m_pCertExtension)
				{
					AUTHORITY_INFO_ACCESS *pAuthInfoAccess = (AUTHORITY_INFO_ACCESS *)::X509V3_EXT_d2i(m_pCertExtension);
					if(!pAuthInfoAccess)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}

					sk_ACCESS_DESCRIPTION_push(pAuthInfoAccess, Info.m_pAccessDesc);


				}
				else
				{
					AUTHORITY_INFO_ACCESS *pAuthInfoAccess = sk_ACCESS_DESCRIPTION_new_null();
					sk_ACCESS_DESCRIPTION_push(pAuthInfoAccess, ACCESS_DESCRIPTION_dup(Info.m_pAccessDesc));

					m_pCertExtension = ::X509V3_EXT_i2d(NID_info_access, 0, pAuthInfoAccess);
					if(!m_pCertExtension)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}
			}
		}
	}
}

