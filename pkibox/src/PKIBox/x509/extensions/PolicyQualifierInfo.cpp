
#include "PolicyQualifierInfo.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/asn1t.h>

#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "../../asn1/OIDs.h"
#include "UserNotice.h"
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
			PolicyQualifierInfo::PolicyQualifierInfo(void) : m_pPolicyQualifierInfo(NULL)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			PolicyQualifierInfo::~PolicyQualifierInfo(void)
			{
				if(m_pPolicyQualifierInfo)
					POLICYQUALINFO_free(m_pPolicyQualifierInfo);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: PolicyQualifierInfo
			// Description	    : Creates a new PolicyQualifierInfo from a user notice qualifier specified by reference information and/or an explicit text.  
			// Return type		: 
			// Argument         : const ObjectID &organization, vector<int> noticeNumbers, const ObjectID &explicitText
			//---------------------------------------------------------------------------------------
			PolicyQualifierInfo::PolicyQualifierInfo(const UserNotice &UserNotice) : m_pPolicyQualifierInfo(NULL)
			{
				m_pPolicyQualifierInfo = POLICYQUALINFO_new();
				if(!m_pPolicyQualifierInfo)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pPolicyQualifierInfo->pqualid = ASN1_OBJECT_dup(asn1::OIDs::id_qt_unotice.m_pObjectID);
				m_pPolicyQualifierInfo->d.usernotice = USERNOTICE_dup(UserNotice.m_pUserNotice);
				if(!m_pPolicyQualifierInfo->d.usernotice)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: PolicyQualifierInfo
			// Description	    : Creates a new PolicyQualifierInfo from a CPS Pointer qualifier.  
			// Return type		: 
			// Argument         : const CByteArray &CpsUri
			//---------------------------------------------------------------------------------------
			PolicyQualifierInfo::PolicyQualifierInfo(const string &CpsUri) : m_pPolicyQualifierInfo(NULL)
			{
				if(!m_pPolicyQualifierInfo)
				{
					m_pPolicyQualifierInfo = POLICYQUALINFO_new();
					if(!m_pPolicyQualifierInfo)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				if(!m_pPolicyQualifierInfo->d.cpsuri)
				{
					m_pPolicyQualifierInfo->d.cpsuri = ASN1_IA5STRING_new();
					if(!m_pPolicyQualifierInfo->d.cpsuri)
					{
						if(m_pPolicyQualifierInfo)
							POLICYQUALINFO_free(m_pPolicyQualifierInfo);

						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				m_pPolicyQualifierInfo->pqualid = ASN1_OBJECT_dup( asn1::OIDs::id_qt_cps.m_pObjectID );
				if(!m_pPolicyQualifierInfo->pqualid)
				{
					if(m_pPolicyQualifierInfo->d.cpsuri)
						ASN1_IA5STRING_free(m_pPolicyQualifierInfo->d.cpsuri);

					if(m_pPolicyQualifierInfo)
						POLICYQUALINFO_free(m_pPolicyQualifierInfo);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				int iRet = ASN1_STRING_set( m_pPolicyQualifierInfo->d.cpsuri, CpsUri.data(), CpsUri.size() );
				if( iRet == -1 )
				{
					if(m_pPolicyQualifierInfo->d.cpsuri)
						ASN1_IA5STRING_free(m_pPolicyQualifierInfo->d.cpsuri);

					if(m_pPolicyQualifierInfo)
						POLICYQUALINFO_free(m_pPolicyQualifierInfo);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: PolicyQualifierInfo
			// Description	    : Copy Constructor
			// Return type		: 
			// Argument         : const PolicyQualifierInfo &PQInfo
			//---------------------------------------------------------------------------------------
			PolicyQualifierInfo::PolicyQualifierInfo(const PolicyQualifierInfo &rhs) : m_pPolicyQualifierInfo(NULL)
			{
				m_pPolicyQualifierInfo = ::POLICYQUALINFO_dup(rhs.m_pPolicyQualifierInfo);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: operator=
			// Description	    : Copy assignment operator.
			// Return type		: PolicyQualifierInfo &
			// Argument         : const PolicyQualifierInfo &rhs
			//---------------------------------------------------------------------------------------
			PolicyQualifierInfo & PolicyQualifierInfo::operator=(const PolicyQualifierInfo &rhs)
			{
				// Check for self assignment
				if (this == &rhs) 
					return *this;

				// delete already allocated memory
				if(m_pPolicyQualifierInfo)
					POLICYQUALINFO_free(m_pPolicyQualifierInfo);

				// Assign new values
				m_pPolicyQualifierInfo = ::POLICYQUALINFO_dup(rhs.m_pPolicyQualifierInfo);

				return *this;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			asn1::ObjectID PolicyQualifierInfo::GetPolicyQualifierID() const
			{
				if(!m_pPolicyQualifierInfo)
				{
					throw Exception("There isn't any PolicyQualifierInfo to get PolicyQualifierID from.");
				}

				asn1::ObjectID PolicyQualifierID;
				PolicyQualifierID.m_pObjectID = ASN1_OBJECT_dup(m_pPolicyQualifierInfo->pqualid);
				return PolicyQualifierID;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetCPSuri
			// Description	    : Gets the CPSUri or null if this PolicyQualifierInfo is not a CPS Pointer. 
			// Return type		: CByteArray 
			// Argument         : void
			//---------------------------------------------------------------------------------------
			string PolicyQualifierInfo::GetCPSuri() const
			{
				if(!m_pPolicyQualifierInfo)
					throw NullPointerException("There is no PolicyQualifierInfo to get CPSuri from.");

				if( asn1::OIDs::id_qt_cps == GetPolicyQualifierID() )
				{
					return string( (char *)m_pPolicyQualifierInfo->d.cpsuri->data, 
						m_pPolicyQualifierInfo->d.cpsuri->length);
				}

				return "";
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			auto_ptr<UserNotice> PolicyQualifierInfo::GetUserNotice() const
			{
				if(!m_pPolicyQualifierInfo)
					throw NullPointerException("There is no PolicyQualifierInfo to get UserNotice from.");

				if( asn1::OIDs::id_qt_unotice == GetPolicyQualifierID() )
				{
					auto_ptr<UserNotice> pUserNotice( new UserNotice );
					pUserNotice->m_pUserNotice = USERNOTICE_dup(m_pPolicyQualifierInfo->d.usernotice);
					return pUserNotice;
				}

				return auto_ptr<UserNotice>(NULL);
			}
		}
	}

}
