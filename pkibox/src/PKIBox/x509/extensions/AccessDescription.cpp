
#include "AccessDescription.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "../../asn1/ObjectID.h"
#include "../../asn1/GeneralName.h"
using namespace std;

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//---------------------------------------------------------------------------------------
			// Function name	: AccessDescription() 
			// Description	    : Default constructor. Initializes m_pAccessDesc to be NULL.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			AccessDescription::AccessDescription(void) : m_pAccessDesc(NULL)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			AccessDescription::AccessDescription(const asn1::ObjectID &Method, const asn1::GeneralName &Location)
			{
				m_pAccessDesc = ::ACCESS_DESCRIPTION_new();
				if(!m_pAccessDesc)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pAccessDesc->method = ASN1_OBJECT_dup(Method.m_pObjectID);
				m_pAccessDesc->location = GENERAL_NAME_dup(Location.m_pName);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: ~AccessDescription()
			// Description	    : Destructor.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			AccessDescription::~AccessDescription(void)
			{
				if(m_pAccessDesc)
				{
					::ACCESS_DESCRIPTION_free(m_pAccessDesc);
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			AccessDescription::AccessDescription(const AccessDescription &rhs)
			{
				m_pAccessDesc = ACCESS_DESCRIPTION_dup(rhs.m_pAccessDesc);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			AccessDescription &AccessDescription::operator=(const AccessDescription &rhs)
			{
				// Check for self assignment
				if (this == &rhs) 
					return *this;

				// delete already allocated memory
				if(m_pAccessDesc)
				{
					::ACCESS_DESCRIPTION_free(m_pAccessDesc);
				}

				// Assign new values
				m_pAccessDesc = ACCESS_DESCRIPTION_dup(rhs.m_pAccessDesc);

				return *this;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetAccessMethod()
			// Description	    : Returns the Access Method Object Identifier. This method returns
			//                    the text description of an Access Method Object Identifier got from NSS.
			//					  For Object Identifiers unknown to NSS this method returns Hex representation
			//                    of that particular Object Identifier e.g. 02:EA:45:34........ 
			// Return type		: string
			//						Object Identifier in the form of string.
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			asn1::ObjectID AccessDescription::GetAccessMethod() const
			{
				if(!m_pAccessDesc)
					throw NullPointerException("There is no AccessDescription to get AccessMethod from.");

				asn1::ObjectID ObjectID;
				ObjectID.m_pObjectID = ASN1_OBJECT_dup(m_pAccessDesc->method);
				return ObjectID;

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			void AccessDescription::SetAccessMethod(const asn1::ObjectID &Method)
			{
				if(m_pAccessDesc)
				{
					m_pAccessDesc->method = Method.m_pObjectID;
				}
				else
				{
					m_pAccessDesc = ::ACCESS_DESCRIPTION_new();
					m_pAccessDesc->method = ASN1_OBJECT_dup(Method.m_pObjectID);
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetAccessLocation()
			// Description	    : Returns the Access Location of this AccessDescription. Access location
			//                    is a URL. This URL can be of an OCSPResponder or the online location of
			//                    issuer certificate.
			// Return type		: string
			//						Access location in the form of string.
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			auto_ptr<asn1::GeneralName> AccessDescription::GetAccessLocation() const
			{
				if(!m_pAccessDesc)
					throw NullPointerException("There is no AccessDescription to get AccessLocation from.");

				if(m_pAccessDesc->location)
				{
					auto_ptr<asn1::GeneralName> pGeneralName(new asn1::GeneralName);
					pGeneralName->m_pName = GENERAL_NAME_dup(m_pAccessDesc->location);
					return pGeneralName;
				}

				return auto_ptr<asn1::GeneralName>(NULL);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetAccessLocation()
			// Description	    : Returns the Access Location of this AccessDescription. Access location
			//                    is a URL. This URL can be of an OCSPResponder or the online location of
			//                    issuer certificate.
			// Return type		: string
			//						Access location in the form of string.
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			void AccessDescription::SetAccessLocation(const asn1::GeneralName &Location)
			{
				if(m_pAccessDesc)
				{
					m_pAccessDesc->location = GENERAL_NAME_dup(Location.m_pName);
				}
				else
				{
					m_pAccessDesc = ::ACCESS_DESCRIPTION_new();
					m_pAccessDesc->location = GENERAL_NAME_dup(Location.m_pName);
				}
			}
		}
	}

}

