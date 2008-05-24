
#include "SubjectKeyIdentifier.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../NullPointerException.h"
#include "../../utils/ByteArray.h"
#include "../../asn1/ObjectID.h"
#include "../../asn1/OIDs.h"
#include "../PublicKey.h"

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//---------------------------------------------------------------------------------------
			// Function name	: SubjectKeyIdentifier
			// Description	    : Default constructor, creates an empty SubjectKeyIdentifier object.
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			SubjectKeyIdentifier::SubjectKeyIdentifier(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: ~SubjectKeyIdentifier
			// Description	    : Destructor
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			SubjectKeyIdentifier::~SubjectKeyIdentifier(void)
			{
			}


			//---------------------------------------------------------------------------------------
			// Function name	: SubjectKeyIdentifier
			// Description	    : Creates a SubjectKeyIdentifier extension with a defined identifier. 
			// Return type		: 
			// Argument         : const CByteArray &identifier
			//---------------------------------------------------------------------------------------
			SubjectKeyIdentifier::SubjectKeyIdentifier(const utils::ByteArray &identifier)
			{
				ASN1_OCTET_STRING * pSubjectKeyIdentifier;
				if(m_pCertExtension)
				{
					pSubjectKeyIdentifier = (ASN1_OCTET_STRING *) X509V3_EXT_d2i( m_pCertExtension );
					if(!pSubjectKeyIdentifier)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}
				else
				{
					pSubjectKeyIdentifier = ASN1_OCTET_STRING_new();
					if(!pSubjectKeyIdentifier)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				int iRet = ASN1_OCTET_STRING_set( pSubjectKeyIdentifier, (unsigned char *)identifier.GetData(), identifier.GetLength() );
				if(iRet == -1)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pCertExtension = X509V3_EXT_i2d( NID_subject_key_identifier, 0, ASN1_OCTET_STRING_dup( pSubjectKeyIdentifier ) );
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: SubjectKeyIdentifier
			// Description	    : Creates a SubjectKeyIdentifier extension from the given public key. 
			// Return type		: 
			// Argument         : const PublicKey &publicKey
			//---------------------------------------------------------------------------------------
			SubjectKeyIdentifier::SubjectKeyIdentifier(const PublicKey &publicKey)
			{
				utils::ByteArray identifier = publicKey.GetEncoded();

				ASN1_OCTET_STRING * pSubjectKeyIdentifier;
				if(m_pCertExtension)
				{
					pSubjectKeyIdentifier = (ASN1_OCTET_STRING *) X509V3_EXT_d2i( m_pCertExtension );
					if(!pSubjectKeyIdentifier)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}
				else
				{
					pSubjectKeyIdentifier = ASN1_OCTET_STRING_new();
					if(!pSubjectKeyIdentifier)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				int iRet = ASN1_OCTET_STRING_set( pSubjectKeyIdentifier, (unsigned char *)identifier.GetData(), identifier.GetLength() );
				if(iRet == -1)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pCertExtension = X509V3_EXT_i2d( NID_subject_key_identifier, 0, pSubjectKeyIdentifier );
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: Get
			// Description	    : Returns the identifier of this extension. 
			// Return type		: CByteArray 
			// Argument         : void
			//---------------------------------------------------------------------------------------
			utils::ByteArray SubjectKeyIdentifier::Get()const /* throw (Exception)*/
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no SubjectKeyIdentifier to get Identifier from.");

				ASN1_OCTET_STRING *pSubjectKeyIdentifier = (ASN1_OCTET_STRING *)X509V3_EXT_d2i(m_pCertExtension);
				if(!pSubjectKeyIdentifier)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				return utils::ByteArray( pSubjectKeyIdentifier->data, pSubjectKeyIdentifier->length);

			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetObjectID
			// Description	    : Returns the object ID of this SubjectKeyIdentifier extension 
			// Return type		: ObjectID 
			// Argument         : void
			//---------------------------------------------------------------------------------------
			asn1::ObjectID SubjectKeyIdentifier::GetObjectID()const /* throw (Exception)*/
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no SubjectKeyIdentifier to get ObjectID from.");

				return asn1::OIDs::id_ce_subjectKeyIdentifier;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: Set
			// Description	    : Sets the identifier of this SubjectKeyIdentifier extension.  
			// Return type		: void
			// Argument         : const CByteArray &identifier
			//---------------------------------------------------------------------------------------
			void SubjectKeyIdentifier::Set(const utils::ByteArray &identifier) /* throw (Exception)*/
			{
				ASN1_OCTET_STRING *pSubjectKeyIdentifier = NULL;
				if(m_pCertExtension)
				{
					pSubjectKeyIdentifier = (ASN1_OCTET_STRING *) X509V3_EXT_d2i( m_pCertExtension );
					if(!pSubjectKeyIdentifier)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}
				else
				{
					pSubjectKeyIdentifier = ASN1_OCTET_STRING_new();
					if(!pSubjectKeyIdentifier)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				int iRet = ASN1_OCTET_STRING_set( pSubjectKeyIdentifier, (unsigned char *)identifier.GetData(), identifier.GetLength() );
				if(iRet == -1)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					if(pSubjectKeyIdentifier)
						ASN1_OCTET_STRING_free(pSubjectKeyIdentifier);

					throw Exception(pc);
				}

				m_pCertExtension = X509V3_EXT_i2d( NID_subject_key_identifier, 0, pSubjectKeyIdentifier );
				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					if(pSubjectKeyIdentifier)
						ASN1_OCTET_STRING_free(pSubjectKeyIdentifier);

					throw Exception(pc);
				}
			}
		}
	}

}
