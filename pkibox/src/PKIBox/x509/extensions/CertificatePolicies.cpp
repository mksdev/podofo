
#include "CertificatePolicies.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../Exception.h"
#include "../../NullPointerException.h"
#include "PolicyInformation.h"
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
			CertificatePolicies::CertificatePolicies(void)
			{
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			CertificatePolicies::~CertificatePolicies(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: CertificatePolicies
			// Description	    : Creates a Certificate Policy object from the given Policy Information.
			// Return type		: 
			// Argument         : const vector<PolicyInformation> &vPolicyInformation
			//---------------------------------------------------------------------------------------
			CertificatePolicies::CertificatePolicies( const vector<PolicyInformation> &vPolicyInformation )
			{
				STACK_OF(POLICYINFO) *pPolicyInfo = sk_POLICYINFO_new_null();
				if(!pPolicyInfo)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);			
				}

				vector<PolicyInformation>::const_iterator itBegin = vPolicyInformation.begin();
				vector<PolicyInformation>::const_iterator itEnd = vPolicyInformation.end();

				for( ; itBegin!=itEnd ; ++itBegin )
				{
					PolicyInformation PI = *itBegin;

					POLICYINFO * pPI = POLICYINFO_dup( PI.m_pPolicyInfo );
					if(!pPI)
						continue;

					sk_POLICYINFO_push( pPolicyInfo, pPI);
				}

				m_pCertExtension = ::X509V3_EXT_i2d( NID_certificate_policies, 0, pPolicyInfo );
				if(!m_pCertExtension)
				{
					if(pPolicyInfo)
						sk_POLICYINFO_free(pPolicyInfo);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(pPolicyInfo)
					sk_POLICYINFO_free(pPolicyInfo);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetPolicyInformation
			// Description	    : Returns the Certificate Policies. 
			// Return type		: vector<PolicyInformation>
			// Argument         : void
			//---------------------------------------------------------------------------------------
			vector<PolicyInformation> CertificatePolicies::GetPolicyInformation()const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no CertificatePolicy to get the PolicyInformation from.");

				STACK_OF(POLICYINFO) *pPolicyInfo = (STACK_OF(POLICYINFO) *) ::X509V3_EXT_d2i( m_pCertExtension );
				if(!pPolicyInfo)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				vector<PolicyInformation> vecPolicyInformation;

				int nPolicyCount = sk_POLICYINFO_num( pPolicyInfo );
				for( int nCount=0 ; nCount<nPolicyCount ; nCount++ )
				{
					PolicyInformation PI;
					PI.m_pPolicyInfo = sk_POLICYINFO_value( pPolicyInfo, nCount );
					vecPolicyInformation.push_back( PI );
				}

				if(pPolicyInfo)
					sk_POLICYINFO_free(pPolicyInfo);

				return vecPolicyInformation;
			}
		}
	}
}

