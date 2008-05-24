
#include "BasicConstraints.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../NullPointerException.h"

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
			BasicConstraints::BasicConstraints(void) 
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			BasicConstraints::~BasicConstraints(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: SetCA
			// Description	    : Sets the cA value of this BasicConstraints extension to true if the subject is a CA. 
			// Return type		: void
			// Argument         : bool bCA
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void BasicConstraints::SetCA(bool bCA) /* throw (Exception)*/
			{
				BASIC_CONSTRAINTS *pBasicConstraint = NULL;
				if(m_pCertExtension)
				{
					pBasicConstraint = (BASIC_CONSTRAINTS *)::X509V3_EXT_d2i(m_pCertExtension);
					if(!pBasicConstraint)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}
				else
				{
					pBasicConstraint = BASIC_CONSTRAINTS_new();
					if(!pBasicConstraint)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				pBasicConstraint->ca = bCA;

				//It is supposed to be critical.
				m_pCertExtension = ::X509V3_EXT_i2d(NID_basic_constraints, 1, pBasicConstraint);
				if(!m_pCertExtension)
				{
					if(pBasicConstraint)
						BASIC_CONSTRAINTS_free(pBasicConstraint);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(pBasicConstraint)
					BASIC_CONSTRAINTS_free(pBasicConstraint);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: SetPathLenConstraint
			// Description	    : Sets the pathLenConstraint value of this BasicConstraints extension specifying the maximum number of CA certificates that may follow the certificate in a certification path. 
			// Return type		: void
			// Argument         : int nPathLength
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void BasicConstraints::SetPathLenConstraint(int nPathLength)/* throw (Exception) */
			{
				BASIC_CONSTRAINTS *pBasicConstraint = NULL;
				if(m_pCertExtension)
				{
					pBasicConstraint = (BASIC_CONSTRAINTS *)::X509V3_EXT_d2i(m_pCertExtension);
					if(!pBasicConstraint)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}
				else
				{
					pBasicConstraint = BASIC_CONSTRAINTS_new();
					if(!pBasicConstraint)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				pBasicConstraint->pathlen = ASN1_INTEGER_new();
				if(!pBasicConstraint->pathlen)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					if(pBasicConstraint)
						BASIC_CONSTRAINTS_free(pBasicConstraint);

					throw Exception(pc);
				}

				int iRet = ASN1_INTEGER_set(pBasicConstraint->pathlen, nPathLength);
				if(iRet == -1)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					if(pBasicConstraint)
						BASIC_CONSTRAINTS_free(pBasicConstraint);
					
					throw Exception(pc);
				}

				//It is supposed to be critical
				m_pCertExtension = ::X509V3_EXT_i2d(NID_basic_constraints, 1, pBasicConstraint);
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					if(pBasicConstraint)
						BASIC_CONSTRAINTS_free(pBasicConstraint);

					throw Exception(pc);
				}

				if(pBasicConstraint)
					BASIC_CONSTRAINTS_free(pBasicConstraint);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			bool BasicConstraints::GetCA() const /* throw (Exception) */
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no BasicConstraints to get CA from.");

				BASIC_CONSTRAINTS *pBasicConstraint = (BASIC_CONSTRAINTS *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pBasicConstraint)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				bool bReturn = pBasicConstraint->ca != 0;

				if(pBasicConstraint)
					::BASIC_CONSTRAINTS_free(pBasicConstraint);

				return bReturn;

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			int BasicConstraints::GetPathLenConstraint() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no BasicConstraints to get PathLenConstraint from.");

				BASIC_CONSTRAINTS *pBasicConstraint = (BASIC_CONSTRAINTS *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pBasicConstraint)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				long lReturn = ::ASN1_INTEGER_get(pBasicConstraint->pathlen);

				if(pBasicConstraint)
					::BASIC_CONSTRAINTS_free(pBasicConstraint);

				return lReturn;
			}
		}
	}

}

