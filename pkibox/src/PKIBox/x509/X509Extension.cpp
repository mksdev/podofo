
#include "X509Extension.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509.h>

#include "../openssl/Globals.h"
#include "../NullPointerException.h"
#include "../utils/ByteArray.h"
#include "../asn1/ObjectID.h"

namespace PKIBox
{
	namespace x509
	{
		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Extension::X509Extension()  : m_pCertExtension(NULL)
		{

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		/*virtual*/ X509Extension::~X509Extension()
		{
			if(m_pCertExtension)
			{
				::X509_EXTENSION_free(m_pCertExtension);
			}
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Extension::X509Extension(const X509Extension &rhs)
		{
			m_pCertExtension = X509_EXTENSION_dup(rhs.m_pCertExtension);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509Extension &X509Extension::operator=(const X509Extension &rhs)
		{
			// Check for self assignment
			if (this == &rhs) 
				return *this;

			// delete already allocated memory
			if(m_pCertExtension)
			{
				::X509_EXTENSION_free(m_pCertExtension);
			}

			// Assign new values
			m_pCertExtension = X509_EXTENSION_dup(rhs.m_pCertExtension);

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		bool X509Extension::IsCritical() const
		{
			if(!m_pCertExtension)
				throw NullPointerException("There is no X509Extension to check criticality of.");

			return ::X509_EXTENSION_get_critical(m_pCertExtension) != 0;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		asn1::ObjectID X509Extension::GetOID()
		{
			if(!m_pCertExtension)
				throw NullPointerException("There is no X509Extension to get OID from.");

			ASN1_OBJECT *pObjectID = ::X509_EXTENSION_get_object(m_pCertExtension);
			if(!pObjectID)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			asn1::ObjectID ObjectID;
			ObjectID.m_pObjectID = ASN1_OBJECT_dup(pObjectID);

			return ObjectID;

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		utils::ByteArray X509Extension::GetValue() const
		{
			if(!m_pCertExtension)
				throw NullPointerException("There is no X509Extension to get value of.");

			if(m_pCertExtension->value)
				if(m_pCertExtension->value->data)
					return utils::ByteArray(m_pCertExtension->value->data, 
					m_pCertExtension->value->length);

			return utils::ByteArray();

		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509Extension::SetOID(const asn1::ObjectID  &obj)
		{
			if(!m_pCertExtension)
			{
				m_pCertExtension = X509_EXTENSION_new();
			}
			else
				ASN1_OBJECT_free( m_pCertExtension->object );

			m_pCertExtension->object = ASN1_OBJECT_dup( obj.m_pObjectID );
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509Extension::SetCritical( bool bCritical)
		{
			if(!m_pCertExtension)
				m_pCertExtension = X509_EXTENSION_new();

			m_pCertExtension->critical = bCritical;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509Extension::SetValue(const utils::ByteArray &baValue)
		{
			if(!m_pCertExtension)
			{
				m_pCertExtension = X509_EXTENSION_new();
				m_pCertExtension->value = ASN1_OCTET_STRING_new();
			}

			ASN1_OCTET_STRING_set(m_pCertExtension->value ,(unsigned char *)baValue.GetData(),baValue.GetLength() );
		}
	}
}

