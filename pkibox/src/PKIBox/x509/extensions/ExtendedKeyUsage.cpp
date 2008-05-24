
#include "ExtendedKeyUsage.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "../../asn1/ObjectID.h"
using namespace std;

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//---------------------------------------------------------------------------------------
			// Function name	: ExtendedKeyUsage()
			// Description	    : Default constructor. Constructs an empty ExtKeyUsage object.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			ExtendedKeyUsage::ExtendedKeyUsage(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: ~ExtendedKeyUsage(void)
			// Description	    : Destructor.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			ExtendedKeyUsage::~ExtendedKeyUsage(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: AddKeyPurposeID
			// Description	    : Inserts a KeyPurposeID specified by OID.
			// Return type		: const ObjectID &OID
			// Argument         : void
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void ExtendedKeyUsage::AddKeyPurposeID(const asn1::ObjectID &OID) /* throw (Exception)*/
			{
				EXTENDED_KEY_USAGE *pExtKeyUsage = NULL;
				if(m_pCertExtension)
				{
					pExtKeyUsage = (EXTENDED_KEY_USAGE *)X509V3_EXT_d2i(m_pCertExtension);
					if(!pExtKeyUsage)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}
				else
				{	
					pExtKeyUsage = sk_ASN1_OBJECT_new_null();
					if(!pExtKeyUsage)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				sk_ASN1_OBJECT_push( pExtKeyUsage, ASN1_OBJECT_dup(OID.m_pObjectID) );

				m_pCertExtension = ::X509V3_EXT_i2d(NID_ext_key_usage, 0, pExtKeyUsage);
				if(!m_pCertExtension)
				{
					if(pExtKeyUsage)
						sk_ASN1_OBJECT_free(pExtKeyUsage);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(pExtKeyUsage)
					sk_ASN1_OBJECT_free(pExtKeyUsage);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: RemoveKeyPurposeID
			// Description	    : Remove the KeyPurposeID specified by OID.
			// Return type		: void
			// Argument         : const ObjectID &OID
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void ExtendedKeyUsage::RemoveKeyPurposeID(const asn1::ObjectID &OID) /* throw (Exception)*/
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no ExtendedKeyUsage extension to remove KeyPurposeIDs from.");

				EXTENDED_KEY_USAGE *pExtKeyUsage = (EXTENDED_KEY_USAGE *)X509V3_EXT_d2i(m_pCertExtension);
				if(!pExtKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				EXTENDED_KEY_USAGE *pTempExtKeyUsage = sk_ASN1_OBJECT_new_null();

				asn1::ObjectID ExtVal;
				while( (ExtVal.m_pObjectID = sk_ASN1_OBJECT_pop(pExtKeyUsage)) ) 
				{
					if(  ExtVal != OID )
					{
						sk_ASN1_OBJECT_push( pTempExtKeyUsage, ASN1_OBJECT_dup(ExtVal.m_pObjectID) );
					}
				}

				m_pCertExtension = ::X509V3_EXT_i2d(NID_ext_key_usage, 0, pTempExtKeyUsage);
				if(!m_pCertExtension)
				{
					if(pTempExtKeyUsage)
						sk_ASN1_OBJECT_free(pTempExtKeyUsage);

					if(pExtKeyUsage)					
						sk_ASN1_OBJECT_free(pExtKeyUsage);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(pTempExtKeyUsage)
					sk_ASN1_OBJECT_free(pTempExtKeyUsage);

				if(pExtKeyUsage)
					sk_ASN1_OBJECT_free(pExtKeyUsage);

			}


			//---------------------------------------------------------------------------------------
			// Function name	: RemoveAllKeyPurposeIDs
			// Description	    : Removes all the KeyPurposeID from this extension.
			// Return type		: void
			// Argument         : void
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void ExtendedKeyUsage::RemoveAllKeyPurposeIDs() /* throw (Exception)*/
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no ExtendedKeyUsage extension to remove KeyPurposeIDs from.");

				EXTENDED_KEY_USAGE *pExtKeyUsage = (EXTENDED_KEY_USAGE *)X509V3_EXT_d2i(m_pCertExtension);
				if(!pExtKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}


				while(sk_ASN1_OBJECT_pop(pExtKeyUsage))
				{
				}
				//int nCount = sk_ASN1_OBJECT_num(pExtKeyUsage);
				//for(int iCount=0 ; iCount<nCount ; iCount++)
				//{
				//	sk_ASN1_OBJECT_delete(pExtKeyUsage, iCount);
				//}

				m_pCertExtension = ::X509V3_EXT_i2d(NID_ext_key_usage, 0, pExtKeyUsage);
				if(!m_pCertExtension)
				{
					if(pExtKeyUsage)
						sk_ASN1_OBJECT_free(pExtKeyUsage);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(pExtKeyUsage)
					sk_ASN1_OBJECT_free(pExtKeyUsage);

			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetNumberofKeyPurposeIDs()
			// Description	    : Returns total number of KeyPurposeIDs in this ExtendedKeyUsage extension.
			// Return type		: unsigned int
			//						Total number of KeyPurposeIDs.
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			unsigned int ExtendedKeyUsage::GetNumberofKeyPurposeIDs() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no ExtendedKeyUsage to get number of KeyPurposeIDs from.");

				EXTENDED_KEY_USAGE *pExtKeyUsage = (EXTENDED_KEY_USAGE *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pExtKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				int iResult = ::sk_num(pExtKeyUsage);

				if(pExtKeyUsage)
					::EXTENDED_KEY_USAGE_free(pExtKeyUsage);

				return iResult;

			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetKeyPurposeID()
			// Description	    : Returns a KeyPurposeID specified by index.
			// Return type		: string
			//						KeyPurposeID
			// Argument         : unsigned int index
			//						Index of KeyPurposeID to get.
			//---------------------------------------------------------------------------------------
			auto_ptr<asn1::ObjectID> ExtendedKeyUsage::GetKeyPurposeID(unsigned int index) const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no ExtendedKeyUsage to get KeyPurposeID from.");

				EXTENDED_KEY_USAGE *pExtKeyUsage = (EXTENDED_KEY_USAGE *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pExtKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}


				ASN1_OBJECT *pKeyPurposeID = (ASN1_OBJECT *)::sk_value(pExtKeyUsage, index);
				if(pKeyPurposeID)
				{
					auto_ptr<asn1::ObjectID> p(new asn1::ObjectID);
					p->m_pObjectID = ASN1_OBJECT_dup(pKeyPurposeID);

					if(pExtKeyUsage)
						::EXTENDED_KEY_USAGE_free(pExtKeyUsage);

					return p;
				}
				else
				{
					if(pExtKeyUsage)
						::EXTENDED_KEY_USAGE_free(pExtKeyUsage);

					return auto_ptr<asn1::ObjectID>(NULL);
				}


			}

			//---------------------------------------------------------------------------------------
			// Function name	: GetKeyPurposeIDs()
			// Description	    : Returns all KeyPurposeIDs included in this extension.
			// Return type		: auto_ptr< vector<string> >
			//						Smart pointer to an array of KeyPurposeIDs.
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			vector<asn1::ObjectID> ExtendedKeyUsage::GetKeyPurposeIDs() const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no ExtendedKeyUsage to get KeyPurposeIDs from.");

				EXTENDED_KEY_USAGE *pExtKeyUsage = (EXTENDED_KEY_USAGE *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pExtKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				vector<asn1::ObjectID> vKeyPurposes;
				vKeyPurposes.reserve(5);

				int cKeyPurposes = ::sk_num(pExtKeyUsage);
				for(int i=0; i<cKeyPurposes; ++i)
				{
					asn1::ObjectID ObjectID;
					ObjectID.m_pObjectID = ASN1_OBJECT_dup( (ASN1_OBJECT *)::sk_value(pExtKeyUsage, i) );
					vKeyPurposes.push_back(ObjectID);
				}

				if(pExtKeyUsage)
					::EXTENDED_KEY_USAGE_free(pExtKeyUsage);

				return vKeyPurposes;


			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			bool ExtendedKeyUsage::IsKeyPurposeID(const asn1::ObjectID &oid) const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no ExtendedKeyUsage to check KeyPurposeID into.");

				EXTENDED_KEY_USAGE *pExtKeyUsage = (EXTENDED_KEY_USAGE *)::X509V3_EXT_d2i(m_pCertExtension);
				if(!pExtKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				int cKeyPurposes = ::sk_num(pExtKeyUsage);
				for(int i=0; i<cKeyPurposes; ++i)
				{
					if( (ASN1_OBJECT *)::sk_value(pExtKeyUsage, i) == oid.m_pObjectID ) 
					{
						if(pExtKeyUsage)
							::EXTENDED_KEY_USAGE_free(pExtKeyUsage);

						return true;
					}

				}

				if(pExtKeyUsage)
					::EXTENDED_KEY_USAGE_free(pExtKeyUsage);

				return false;

			}


		}
	}
}

