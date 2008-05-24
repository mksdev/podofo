
#include "CRLDistributionPoints.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "CRLDistributionPoint.h"
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
			CRLDistributionPoints::CRLDistributionPoints(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			CRLDistributionPoints::~CRLDistributionPoints(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			unsigned int CRLDistributionPoints::GetNumberOfCDPs() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no CRLDistributionPoints to get number of CDPs from.");

				CRL_DIST_POINTS *pCRLDistPoints = (CRL_DIST_POINTS *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pCRLDistPoints)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				return ::sk_num(pCRLDistPoints);

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			vector<CRLDistributionPoint> CRLDistributionPoints::GetCDPs() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no CRLDistributionPoints to get CDPs from.");

				CRL_DIST_POINTS *pCRLDistPoints = (CRL_DIST_POINTS *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pCRLDistPoints)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				vector<CRLDistributionPoint> vCRLDistPoints;
				vCRLDistPoints.reserve(2);

				int cCDPs = ::sk_num(pCRLDistPoints);
				for(int i=0; i<cCDPs; ++i)
				{
					CRLDistributionPoint CRLDistPoint;
					CRLDistPoint.m_pCRLDistPoint = DIST_POINT_dup( (DIST_POINT *)sk_value(pCRLDistPoints, i) );
					vCRLDistPoints.push_back(CRLDistPoint);
				}

				if(pCRLDistPoints)
				{
					CRL_DIST_POINTS_free(pCRLDistPoints);
				}

				return vCRLDistPoints;

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			auto_ptr<CRLDistributionPoint> CRLDistributionPoints::GetCDP(unsigned int n) const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no CRLDistributionPoints to get CDP from.");

				CRL_DIST_POINTS *pCRLDistPoints = (CRL_DIST_POINTS *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pCRLDistPoints)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				DIST_POINT *pCRLDistPoint = (DIST_POINT *)::sk_value(pCRLDistPoints, n);
				if(pCRLDistPoint)
				{
					auto_ptr<CRLDistributionPoint> p(new CRLDistributionPoint);
					p->m_pCRLDistPoint = pCRLDistPoint;
					return p;
				}
				else
					return auto_ptr<CRLDistributionPoint>(NULL);

			}


			//---------------------------------------------------------------------------------------
			// Function name	: AddCDP
			// Description	    : Inserts the CDP in the extension.
			// Return type		: void
			// Argument         : const CRLDistributionPoint &CDP
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void CRLDistributionPoints::AddCDP(const CRLDistributionPoint &CDP) /* throw (Exception)*/
			{
				CRL_DIST_POINTS * pCRLDistPoints = NULL;

				if(m_pCertExtension)
				{
					pCRLDistPoints = (CRL_DIST_POINTS *)::X509V3_EXT_d2i(m_pCertExtension);
					if(!pCRLDistPoints)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}			
				}
				else
				{
					pCRLDistPoints = sk_DIST_POINT_new_null();
					if(!pCRLDistPoints)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				sk_DIST_POINT_push( pCRLDistPoints, DIST_POINT_dup(CDP.m_pCRLDistPoint) );

				m_pCertExtension = ::X509V3_EXT_i2d( NID_crl_distribution_points, 0, pCRLDistPoints );
				if(!m_pCertExtension)
				{
					if(pCRLDistPoints)
						sk_DIST_POINT_free(pCRLDistPoints);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(pCRLDistPoints)
					sk_DIST_POINT_free(pCRLDistPoints);
			}
		}
	}
}

