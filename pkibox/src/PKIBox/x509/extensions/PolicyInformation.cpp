
#include "PolicyInformation.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "../../asn1/ObjectID.h"
#include "PolicyQualifierInfo.h"
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
			PolicyInformation::PolicyInformation(void) : m_pPolicyInfo(NULL)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			PolicyInformation::~PolicyInformation(void)
			{
				if(m_pPolicyInfo)
					POLICYINFO_free(m_pPolicyInfo);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: PolicyInformation 
			// Description	    : Creates a new PolicyInformation object from given policy id and policy qualifiers.
			// Return type		: 
			// Argument         : const ObjectID &OID, const vector<PolicyQualifierInfo> &vecPolicyQualifierInfo
			//---------------------------------------------------------------------------------------
			PolicyInformation::PolicyInformation( const asn1::ObjectID &OID, const vector<PolicyQualifierInfo> &vecPolicyQualifierInfo ) : m_pPolicyInfo(NULL)
			{
				if(!m_pPolicyInfo)
				{
					m_pPolicyInfo = POLICYINFO_new();
					if(!m_pPolicyInfo)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);			
					}
				}

				if(!m_pPolicyInfo->qualifiers)
				{
					m_pPolicyInfo->qualifiers = sk_POLICYQUALINFO_new_null();
					if(!m_pPolicyInfo->qualifiers)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);			
					}
				}

				m_pPolicyInfo->policyid = ASN1_OBJECT_dup( OID.m_pObjectID );
				if(!m_pPolicyInfo->policyid)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);			
				}

				vector<PolicyQualifierInfo>::const_iterator itBegin = vecPolicyQualifierInfo.begin();
				vector<PolicyQualifierInfo>::const_iterator itEnd = vecPolicyQualifierInfo.end();

				for( ; itBegin!=itEnd ; ++itBegin)
				{
					PolicyQualifierInfo policyQualifierInfo = *itBegin;
					sk_POLICYQUALINFO_push( m_pPolicyInfo->qualifiers, POLICYQUALINFO_dup( policyQualifierInfo.m_pPolicyQualifierInfo ) );
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: PolicyInformation 
			// Description	    : Copy Constructor
			// Return type		: 
			// Argument         : const PolicyInformation &PolicyInfo
			//---------------------------------------------------------------------------------------
			PolicyInformation::PolicyInformation(const PolicyInformation &PolicyInfo)
			{
				m_pPolicyInfo = POLICYINFO_dup( PolicyInfo.m_pPolicyInfo );
			}


			//---------------------------------------------------------------------------------------
			// Function name	: operator=
			// Description	    : Copy assignment operator.
			// Return type		: PolicyInformation & 
			// Argument         : const PolicyInformation &rhs
			//---------------------------------------------------------------------------------------
			PolicyInformation & PolicyInformation::operator=(const PolicyInformation &rhs)
			{
				// Check for self assignment
				if (this == &rhs) 
					return *this;

				// delete already allocated memory
				if(m_pPolicyInfo)
					POLICYINFO_free( m_pPolicyInfo );

				// Assign new values
				m_pPolicyInfo = POLICYINFO_dup( rhs.m_pPolicyInfo );

				return *this;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: PolicyInformation 
			// Description	    : Returns the policy identifier. 
			// Return type		: ObjectID 
			// Argument         : void
			//---------------------------------------------------------------------------------------
			asn1::ObjectID PolicyInformation::GetPolicyIdentifier()const
			{
				if(!m_pPolicyInfo)
					throw NullPointerException("There is no PolicyInfo to get PolicyIdentifier from.");

				asn1::ObjectID OID;
				OID.m_pObjectID = ASN1_OBJECT_dup( m_pPolicyInfo->policyid );
				if(!OID.m_pObjectID)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);			
				}

				return OID;

			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetPolicyQualifiers
			// Description	    : Returns the policy qualifiers. 
			// Return type		: vector<PolicyQualifierInfo>
			// Argument         : void
			//---------------------------------------------------------------------------------------
			vector<PolicyQualifierInfo> PolicyInformation::GetPolicyQualifiers()const
			{
				if(!m_pPolicyInfo)
					throw NullPointerException("There is no PolicyInfo to get PolicyIdentifier from.");

				vector<PolicyQualifierInfo> vecPolicyInfo;

				int nPolicyQualifier = sk_POLICYQUALINFO_num( m_pPolicyInfo->qualifiers );

				for( int iCount=0 ; iCount<nPolicyQualifier ; iCount++ )
				{
					POLICYQUALINFO * pPQI = (POLICYQUALINFO *)sk_POLICYQUALINFO_value( m_pPolicyInfo->qualifiers, iCount );
					if(!pPQI)
						continue;

					POLICYQUALINFO * pDupPQI = POLICYQUALINFO_dup( pPQI );

					PolicyQualifierInfo PQI;
					PQI.m_pPolicyQualifierInfo = pDupPQI;

					vecPolicyInfo.push_back(PQI);
				}

				return vecPolicyInfo;

			}
		}
	}

}
