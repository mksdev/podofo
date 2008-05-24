
#include "KeyUsage.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../NullPointerException.h"
using namespace std;

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//---------------------------------------------------------------------------------------
			// Function name	: KeyUsage()
			// Description	    : Default constructor. Constructs an empty KeyUsage object.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			KeyUsage::KeyUsage(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: ~KeyUsage(void)
			// Description	    : Destructor.
			// Return type		: Nothing
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			KeyUsage::~KeyUsage(void)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: IsSet()
			// Description	    : Returns whether the specified key usage value is set.
			// Return type		: bool
			//						true if the specified key usage value is set and false otherwise.
			// Argument         : const KEYUSAGE Index
			//						KeyUsage value to check for.
			//---------------------------------------------------------------------------------------
			bool KeyUsage::IsSet(const KEYUSAGE Index) const
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no KeyUsage extension to check KeyUsage from.");

				ASN1_BIT_STRING *pKeyUsage = (ASN1_BIT_STRING *) ::X509V3_EXT_d2i(m_pCertExtension);
				if(!pKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				bool bReturn = false;

				switch(Index)
				{
				case digitalSignature:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 0) ? true : false;
					break;
				case nonRepudiation:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 1) ? true : false;
					break;
				case keyEncipherment:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 2) ? true : false;
					break;
				case dataEncipherment:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 3) ? true : false;
					break;					
				case keyAgreement:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 4) ? true : false;
					break;
				case keyCertSign:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 5) ? true : false;
					break;
				case cRLSign:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 6) ? true : false;
					break;
				case encipherOnly:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 7) ? true : false;
					break;
				case decipherOnly:
					bReturn = ASN1_BIT_STRING_get_bit(pKeyUsage, 8) ? true : false;
					break;
				}

				if(pKeyUsage)
				{
					ASN1_BIT_STRING_free(pKeyUsage);
				}

				return bReturn;

			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetKeyUsages()
			// Description	    : Returns all the KeyUsage values in form of a bitset. 
			// Return type		: bitset<KeyUsage::NoofKeyUsages>
			//						bitset containing KeyUsage values.
			// Argument         : Nothing
			//---------------------------------------------------------------------------------------
			bitset<KeyUsage::NoofKeyUsages> KeyUsage::GetKeyUsages()
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no KeyUsage extension to get KeyUsages from.");

				bitset<NoofKeyUsages> tmpBitSet;

				ASN1_BIT_STRING *pKeyUsage = (ASN1_BIT_STRING *) ::X509V3_EXT_d2i(m_pCertExtension);
				if(!pKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 0) )
					tmpBitSet.set(0, true);

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 1) )
					tmpBitSet.set(1, true);

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 2) )
					tmpBitSet.set(2, true);

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 3) )
					tmpBitSet.set(3, true);

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 4) )
					tmpBitSet.set(4, true);

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 5) )
					tmpBitSet.set(5, true);

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 6) )
					tmpBitSet.set(6, true);

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 7) )
					tmpBitSet.set(7, true);

				if( ASN1_BIT_STRING_get_bit(pKeyUsage, 8) )
					tmpBitSet.set(8, true);

				if(pKeyUsage)
				{
					ASN1_BIT_STRING_free(pKeyUsage);
				}

				return tmpBitSet;

			}


			//---------------------------------------------------------------------------------------
			// Function name	: SetKeyUsage
			// Description	    : Set the specific key usage specified by the KEYUSAGE index.
			// Return type		: void
			// Argument         : const KEYUSAGE Index
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void KeyUsage::SetKeyUsage(const KEYUSAGE Index) const /* throw (Exception)*/
			{
				if(!m_pCertExtension)
					throw NullPointerException("There is no KeyUsage extension to set KeyUsages in.");

				//ASN1_BIT_STRING *bsKeyUsage = (ASN1_BIT_STRING *)::X509V3_EXT_d2i(m_pCertExtension);
				ASN1_BIT_STRING *bsKeyUsage = ASN1_BIT_STRING_new();
				if(!bsKeyUsage)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				switch(Index) 
				{
				case digitalSignature:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 0, true );
					break;

				case nonRepudiation:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 1, true );
					break;

				case keyEncipherment:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 2, true );
					break;

				case dataEncipherment:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 3, true );
					break;

				case keyAgreement:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 4, true );
					break;

				case keyCertSign:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 5, true );
					break;

				case cRLSign:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 6, true );
					break;

				case encipherOnly:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 7, true );
					break;

				case decipherOnly:
					ASN1_BIT_STRING_set_bit( bsKeyUsage, 8, true );
					break;
				}

				//m_pCertExtension = ::X509V3_EXT_i2d( NID_key_usage, 0, bsKeyUsage );

				if(!m_pCertExtension)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

			}


			//---------------------------------------------------------------------------------------
			// Function name	: SetKeyUsages
			// Description	    : Sets KeyUsage value in form of a bitset.
			// Return type		: void
			// Argument         : const bitset<NoofKeyUsages> &keyUsage
			//						bitset containing the bit sequence of the usages.
			// Code Added By	: GA
			//---------------------------------------------------------------------------------------
			void KeyUsage::SetKeyUsages( const bitset<NoofKeyUsages> &keyUsage ) /* throw (Exception)*/
			{
				if(!m_pCertExtension)
				{
					m_pCertExtension = X509_EXTENSION_new();
					if(!m_pCertExtension)
					{
						const char *pc = ::ERR_reason_error_string(::ERR_get_error());
						throw Exception(pc);
					}
				}

				ASN1_BIT_STRING * bsKeyUsage = ASN1_BIT_STRING_new();

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 0, keyUsage[0] );

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 1, keyUsage[1] );

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 2, keyUsage[2] );

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 3, keyUsage[3] );

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 4, keyUsage[4] );

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 5, keyUsage[5] );

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 6, keyUsage[6] );

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 7, keyUsage[7] );

				ASN1_BIT_STRING_set_bit(bsKeyUsage, 8, keyUsage[8] );

				//This extension always be critical
				m_pCertExtension = ::X509V3_EXT_i2d(NID_key_usage, 1, bsKeyUsage);
				if(!m_pCertExtension)
				{
					if(bsKeyUsage)
						ASN1_BIT_STRING_free(bsKeyUsage);

					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				if(bsKeyUsage)
					ASN1_BIT_STRING_free(bsKeyUsage);
			}

		}
	}
}

