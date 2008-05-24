
#include "HoldInstructionCode.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../Exception.h"
#include "../../NullPointerException.h"
#include "../../asn1/ObjectID.h"

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			asn1::ObjectID HoldInstructionCode::s_holdInstructionNone("1.2.840.10040.2.1"); // The holdinstruction-none oid (1.2.840.10040.2.1).  
			asn1::ObjectID HoldInstructionCode::s_holdInstructionCallIssuer("1.2.840.10040.2.2"); // The holdinstruction-callissuer oid (1.2.840.10040.2.2).  
			asn1::ObjectID HoldInstructionCode::s_holdInstructionReject("1.2.840.10040.2.3"); // The holdinstruction-reject oid (1.2.840.10040.2.3).  

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			HoldInstructionCode::HoldInstructionCode(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			HoldInstructionCode::~HoldInstructionCode(void)
			{
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			HoldInstructionCode::HoldInstructionCode(const asn1::ObjectID &instructionCode)
			{
				m_pCertExtension = ::X509V3_EXT_i2d(NID_hold_instruction_code, 0, instructionCode.m_pObjectID); 
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			asn1::ObjectID HoldInstructionCode::GetHoldInstructionCode() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no HoldInstructionCode to get HoldInstructionCode from.");

				ASN1_OBJECT *pHoldInstructionCode = (ASN1_OBJECT *) ::X509V3_EXT_d2i(m_pCertExtension);
				if(!pHoldInstructionCode)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				asn1::ObjectID holdInstructionCode;
				holdInstructionCode.m_pObjectID = pHoldInstructionCode;
				return holdInstructionCode;
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			void HoldInstructionCode::SetInstructionCode(const asn1::ObjectID &instructionCode)
			{
				X509_EXTENSION *pCertExtension = ::X509V3_EXT_i2d(NID_hold_instruction_code, 0, instructionCode.m_pObjectID); 
				if(!pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(m_pCertExtension)
					::X509_EXTENSION_free(m_pCertExtension);

				m_pCertExtension = pCertExtension;
			}

		}
	}
}


