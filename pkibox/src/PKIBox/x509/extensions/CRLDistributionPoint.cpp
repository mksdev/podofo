
#include "CRLDistributionPoint.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../asn1/ObjectID.h"
#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "../../asn1/GeneralName.h"

using namespace std;

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//---------------------------------------------------------------------------------------
			// Function name	: CRLDistributionPoint()
			// Description	    : Default constructor. Initializes m_pCRLDistPoint to NULL.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			CRLDistributionPoint::CRLDistributionPoint(void) : m_pCRLDistPoint(NULL)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: ~CRLDistributionPoint()
			// Description	    : Destructor.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			/*virtual*/ CRLDistributionPoint::~CRLDistributionPoint(void)
			{
				if(m_pCRLDistPoint)
					::DIST_POINT_free(m_pCRLDistPoint);
			}

			//---------------------------------------------------------------------------------------
			// Function name	: ~CRLDistributionPoint()
			// Description	    : Destructor.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			CRLDistributionPoint::CRLDistributionPoint(const CRLDistributionPoint &rhs)
			{
				m_pCRLDistPoint = DIST_POINT_dup(rhs.m_pCRLDistPoint);
			}

			//---------------------------------------------------------------------------------------
			// Function name	: ~CRLDistributionPoint()
			// Description	    : Destructor.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			CRLDistributionPoint &CRLDistributionPoint::operator=(const CRLDistributionPoint &rhs)
			{
				// Check for self assignment
				if (this == &rhs) 
					return *this;

				// delete already allocated memory
				if(m_pCRLDistPoint)
					::DIST_POINT_free(m_pCRLDistPoint);

				// Assign new values
				m_pCRLDistPoint = DIST_POINT_dup(rhs.m_pCRLDistPoint);

				return *this;
			}

			//---------------------------------------------------------------------------------------
			// Function name	: SetCRLIssuer
			// Description	    : Sets CRL issuer of this DistributionPoint.
			// Return type		: void
			// Argument         : const vector<GeneralName> &crlIssuer
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void CRLDistributionPoint::SetCRLIssuer(const vector<asn1::GeneralName> &crlIssuer) /* throw (Exception)*/
			{
				if(!m_pCRLDistPoint)
				{
					m_pCRLDistPoint = DIST_POINT_new();
					if(!m_pCRLDistPoint)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				if(!m_pCRLDistPoint->CRLissuer)
				{
					m_pCRLDistPoint->CRLissuer = sk_GENERAL_NAME_new_null();
					if(!m_pCRLDistPoint->CRLissuer)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				vector<asn1::GeneralName>::const_iterator itBegin = crlIssuer.begin();
				vector<asn1::GeneralName>::const_iterator itEnd = crlIssuer.end();

				for( ; itBegin!=itEnd ; ++itBegin)
				{
					sk_GENERAL_NAME_push(m_pCRLDistPoint->CRLissuer, GENERAL_NAME_dup( (*itBegin).m_pName) );
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetCRLIssuer()
			// Description	    : Returns the name of CRL issuer. This method needs to be implemented completely.
			// Return type		: string
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			vector<asn1::GeneralName> CRLDistributionPoint::GetCRLIssuer() const
			{
				if(!m_pCRLDistPoint)
					throw NullPointerException("There is no CRLDistributionPoint to get CRL Issuer from.");

				vector<asn1::GeneralName> vGeneralName;

				if(m_pCRLDistPoint->CRLissuer)
				{
					int cGeneralNames = sk_num(m_pCRLDistPoint->CRLissuer);

					for(int i=0; i < cGeneralNames; ++i)
					{
						asn1::GeneralName GeneralName;
						GeneralName.m_pName = (GENERAL_NAME *)sk_value(m_pCRLDistPoint->CRLissuer, i);
						vGeneralName.push_back(GeneralName);
					}
				}

				return vGeneralName;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: SetReasonFlags()
			// Description	    : Sets the reason flag for this DistributionPoint.
			// Return type		: void
			// Argument         : RevocationReason reason
			//---------------------------------------------------------------------------------------
			void CRLDistributionPoint::SetReasonFlags(RevocationReason reason) /* throw (Exception)*/
			{
				if(!m_pCRLDistPoint)
				{
					m_pCRLDistPoint = DIST_POINT_new();
					if(!m_pCRLDistPoint)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				ASN1_BIT_STRING * bsReasonFlag = ASN1_BIT_STRING_new();

				switch(reason) 
				{
				case unused:
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 0, true );
					break;
				case keyCompromise :
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 1, true );
					break;
				case cACompromise:
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 2, true );
					break;
				case affiliationChanged:
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 3, true );
					break;
				case superseded:
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 4, true );
					break;
				case cessationOfOperation:
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 5, true );
					break;
				case certificateHold:
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 6, true );
					break;
				case privilegeWithdrawn:
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 7, true );
					break;
				case aACompromise:
					ASN1_BIT_STRING_set_bit( bsReasonFlag, 8, true );
					break;
				}

				m_pCRLDistPoint->reasons = ASN1_BIT_STRING_dup(bsReasonFlag);
				if(!m_pCRLDistPoint->reasons)
				{
					if(bsReasonFlag)
						ASN1_BIT_STRING_free(bsReasonFlag);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(bsReasonFlag)
					ASN1_BIT_STRING_free(bsReasonFlag);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetReasonFlags()
			// Description	    : Return Reason flags.
			// Return type		: unsigned char
			//						Reason flags in form of one byte.
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			unsigned char CRLDistributionPoint::GetReasonFlags() const
			{
				if(!m_pCRLDistPoint)
					throw NullPointerException("There is no CRLDistributionPoint to get revocation reason flags from.");

				if(m_pCRLDistPoint->reasons)
					if(m_pCRLDistPoint->reasons->length)
						return *(m_pCRLDistPoint->reasons->data);

				return 0;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: IsReason() 
			// Description	    : Checks for a specific Reason to be present in this CRLDistributionPoint.
			// Return type		: bool
			//						true if a specific reason is present and false otherwise
			// Argument         : ERevReasons Reason
			//						Revocation reason.
			//---------------------------------------------------------------------------------------
			bool CRLDistributionPoint::IsReason(RevocationReason Reason) const 
			{
				if(!m_pCRLDistPoint)
					throw NullPointerException("There is no CRLDistributionPoint to look revocation reason for.");

				return ::ASN1_BIT_STRING_get_bit(m_pCRLDistPoint->reasons, Reason) != 0;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: SetDistributionPointName
			// Description	    : Sets the distribution point name of this DistributionPoint.
			// Return type		: void
			// Argument         : const GeneralName &DPName
			//---------------------------------------------------------------------------------------
			void CRLDistributionPoint::SetDistributionPointName(const asn1::GeneralName &DPName) /* throw (Exception)*/
			{
				if(!m_pCRLDistPoint)
				{
					m_pCRLDistPoint = DIST_POINT_new();
					if(!m_pCRLDistPoint)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				if(!m_pCRLDistPoint->distpoint)
				{
					m_pCRLDistPoint->distpoint = DIST_POINT_NAME_new();
					if(!m_pCRLDistPoint->distpoint)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				if(!m_pCRLDistPoint->distpoint->name.fullname)
				{
					m_pCRLDistPoint->distpoint->name.fullname = sk_GENERAL_NAME_new_null();
					if(!m_pCRLDistPoint->distpoint->name.fullname)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				m_pCRLDistPoint->distpoint->type = 0;
				sk_GENERAL_NAME_push( m_pCRLDistPoint->distpoint->name.fullname, GENERAL_NAME_dup(DPName.m_pName) );
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetDistributionPointName()
			// Description	    : Returns DistributionPointName. i.e. the URL of certificate revocation list.
			// Return type		: string
			//						URL of certificate revocation list.
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			auto_ptr<asn1::GeneralName> CRLDistributionPoint::GetDistributionPointName() const
			{
				if(!m_pCRLDistPoint)
					throw NullPointerException("There is no CRLDistributionPoint to get DistributionPointName from.");

				switch(m_pCRLDistPoint->distpoint->type) 
				{
				case 0:
					{
						auto_ptr<asn1::GeneralName> pGN(new asn1::GeneralName);
						pGN->m_pName = ::GENERAL_NAME_dup( (GENERAL_NAME *)::sk_value(m_pCRLDistPoint->distpoint->name.fullname, 0) );
						return pGN;
					}

				case 1: 
					break;
				}

				return auto_ptr<asn1::GeneralName>(NULL);

			}

		}
	}
}

