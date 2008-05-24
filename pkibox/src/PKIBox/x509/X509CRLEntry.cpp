
#include "X509CRLEntry.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>

#include "../openssl/Globals.h"
#include "../Exception.h"
#include "../NullPointerException.h"
#include "../utils/DateTime.h"
#include "../utils/BigInteger.h"
#include "../asn1/ObjectID.h"
#include "X509Extension.h"
#include "X509Certificate.h"
#include "extensions/InvalidityDate.h"
#include "extensions/ReasonCode.h"


using namespace std;


namespace PKIBox
{
	namespace x509
	{
		//---------------------------------------------------------------------------------------
		// Function name	: X509CRLEntry()
		// Description	    : Default constructor. Initializes m_pCRLEntry to NULL.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		X509CRLEntry::X509CRLEntry() : m_pCRLEntry(NULL)
		{

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		X509CRLEntry::X509CRLEntry(const utils::BigInteger &serialNumber, const utils::DateTime &revocationDate) : m_pCRLEntry(NULL)
		{
			m_pCRLEntry = X509_REVOKED_new();
			if(!m_pCRLEntry)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			ASN1_INTEGER *pSerialNumber = BN_to_ASN1_INTEGER(serialNumber.m_pBN, NULL);
			if(!pSerialNumber)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

            int iRet = X509_REVOKED_set_serialNumber(m_pCRLEntry, pSerialNumber);
			if( -1 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pSerialNumber)
					ASN1_INTEGER_free(pSerialNumber);

				throw Exception(pc);
			}

			ASN1_TIME *pRevocationDate = ::ASN1_TIME_set(NULL, revocationDate.GetTime());
			if(!pRevocationDate)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pSerialNumber)
					ASN1_INTEGER_free(pSerialNumber);

				throw Exception(pc);
			}

			iRet = X509_REVOKED_set_revocationDate(m_pCRLEntry, pRevocationDate);
			if( -1 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pSerialNumber)
					ASN1_INTEGER_free(pSerialNumber);

				if(pRevocationDate)
					::ASN1_TIME_free(pRevocationDate);

				throw Exception(pc);
			}

			if(pSerialNumber)
				ASN1_INTEGER_free(pSerialNumber);

			if(pRevocationDate)
				::ASN1_TIME_free(pRevocationDate);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: ~X509CRLEntry()
		// Description	    : Destructor.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		X509CRLEntry::X509CRLEntry(const x509::X509Certificate &cert, const utils::DateTime &revocationDate) : m_pCRLEntry(NULL)
		{
			m_pCRLEntry = X509_REVOKED_new();
			if(!m_pCRLEntry)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			int iRet = X509_REVOKED_set_serialNumber(m_pCRLEntry, cert.m_pCert->cert_info->serialNumber);
			if( -1 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			ASN1_TIME *pRevocationDate = ::ASN1_TIME_set(NULL, revocationDate.GetTime());
			if(!pRevocationDate)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			iRet = X509_REVOKED_set_revocationDate(m_pCRLEntry, pRevocationDate);
			if( -1 == iRet)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());

				if(pRevocationDate)
					::ASN1_TIME_free(pRevocationDate);

				throw Exception(pc);
			}

			if(pRevocationDate)
				::ASN1_TIME_free(pRevocationDate);
		}

		//---------------------------------------------------------------------------------------
		// Function name	: ~X509CRLEntry()
		// Description	    : Destructor.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		/*virtual*/ X509CRLEntry::~X509CRLEntry()
		{
			if(m_pCRLEntry)
				::X509_REVOKED_free(m_pCRLEntry);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: ~X509CRLEntry()
		// Description	    : Destructor.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		X509CRLEntry::X509CRLEntry(const X509CRLEntry &rhs)
		{
			m_pCRLEntry = X509_REVOKED_dup(rhs.m_pCRLEntry);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: ~X509CRLEntry()
		// Description	    : Destructor.
		// Return type		: Nothing
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		X509CRLEntry &X509CRLEntry::operator=(const X509CRLEntry &rhs)
		{
			// Check for self assignment
			if (this == &rhs) 
				return *this;

			// delete already allocated memory
			if(m_pCRLEntry)
			{
				::X509_REVOKED_free(m_pCRLEntry);
			}

			// Assign new values
			m_pCRLEntry = X509_REVOKED_dup(rhs.m_pCRLEntry);

			return *this;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetRevocationDate()
		// Description	    : Returns the revocation date of this X509CRLEntry. Calls NSS for converting
		//                    time into int64 and then constructs a CDate object from that int64 and
		//                    return it to caller.
		// Return type		: CDate
		//						Revocation date of this X509CRLEntry.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		utils::DateTime X509CRLEntry::GetRevocationDate() const /* throw (Exception) */
		{
			if(!m_pCRLEntry)
				throw NullPointerException("There is no CRLEntry to get revocation date from.");

			time_t Time = ::ASN1_UTCTIME_get(m_pCRLEntry->revocationDate);
			return utils::DateTime(Time);

		}



		//---------------------------------------------------------------------------------------
		// Function name	: GetSerialNumber()
		// Description	    : Returns the serial number of this X509CRLEntry. This method returns
		//                    the hex representation of a serial number as string.
		// Return type		: string
		//						Serial number of this X509CRLEntry.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		utils::BigInteger X509CRLEntry::GetSerialNumber() const /* throw (Exception) */
		{
			if(!m_pCRLEntry)
				throw NullPointerException("There is no CRLEntry to get serial number from.");

			BIGNUM *pBN = ::ASN1_INTEGER_to_BN(m_pCRLEntry->serialNumber, NULL);
			if(!pBN)
			{
				const char *pc = ::ERR_reason_error_string(::ERR_get_error());
				throw Exception(pc);
			}

			utils::BigInteger BN;
			BN.m_pBN = pBN;
			return BN;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator==() 
		// Description	    : Equality operator. Compares two X509CRLEntry objects.
		// Return type		: bool
		//						true if this X509CRLEntry is equal to X509CRLEntry provided otherwise false.
		// Argument         : const X509CRLEntry &CRLEntry
		//						X509CRLEntry to compare with.
		//---------------------------------------------------------------------------------------
		bool X509CRLEntry::operator==(const X509CRLEntry &CRLEntry) const
		{ 
			return GetSerialNumber() == CRLEntry.GetSerialNumber() && 
				GetRevocationDate() == CRLEntry.GetRevocationDate(); 
		}


		//---------------------------------------------------------------------------------------
		// Function name	: operator!=()
		// Description	    : Inequality operator. 
		// Return type		: bool
		//						true if this X509CRLEntry is not equal to X509CRLEntry provided otherwise
		//                      false.
		// Argument         : const X509CRLEntry &CRLEntry
		//						X509CRLEntry to compare with.
		//---------------------------------------------------------------------------------------
		bool X509CRLEntry::operator!=(const X509CRLEntry &CRLEntry) const
		{ 
			return !operator==(CRLEntry);
		}


		//---------------------------------------------------------------------------------------
		// Function name	: HasExtensions()
		// Description	    : Checks whether this X509CRLEntry has extensions or not?
		// Return type		: bool
		//						true if this X509CRLEntry has extensions otherwise false.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		bool X509CRLEntry::HasExtensions() const /* throw (Exception) */
		{
			if(!m_pCRLEntry)
				throw NullPointerException("There isnt any CRLEntry to check extensions for.");

			return m_pCRLEntry->extensions != NULL;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetNumberOfExtensions()
		// Description	    : Returns the total number of extensions present in this X509CRLEntry. 
		//                    This method iterates over NSS array of extensions and just count the 
		//                    number of iterations. In the end it returns this count.
		// Return type		: unsigned int
		//						Total number of extensions present in this X509CRLEntry.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		unsigned int X509CRLEntry::GetNumberOfExtensions() const /* throw (Exception) */
		{
			if(!m_pCRLEntry)
				throw NullPointerException("There is no CRLEntry to get number of extensions from.");

			return ::X509_REVOKED_get_ext_count(m_pCRLEntry);

		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetExtensions()
		// Description	    : Returns all the extensions present in this X509CRLEntry. This method
		//                    iterates over the NSS array of extensions, constructs a X509Extension
		//                    object for each extension, add it to the vector and in the end returns 
		//                    vector to the caller.
		// Return type		: auto_ptr< vector<X509Extension> >
		//						Smart pointer to a vector of extensions.
		// Argument         : Nothing
		//---------------------------------------------------------------------------------------
		std::vector< clone_ptr<x509::X509Extension> > X509CRLEntry::GetExtensions() const /* throw (Exception) */
		{
			if(!m_pCRLEntry)
				throw NullPointerException("There is no CRLEntry to get extensions from.");

			vector< clone_ptr<x509::X509Extension> > vExtensions;
			if(m_pCRLEntry->extensions)
			{
				vExtensions.reserve(4);
				unsigned int cExtensions = GetNumberOfExtensions();

				X509_EXTENSION *pExt = NULL;
				for(int i=0; i<(int)cExtensions; ++i)
				{
					pExt = ::X509_REVOKED_get_ext(m_pCRLEntry, i);
					if(!pExt)
					{
						continue;
					}

					X509Extension *pExtension = new X509Extension;
					pExtension->m_pCertExtension = X509_EXTENSION_dup(pExt);
					vExtensions.push_back(pExtension);
				}
			}

			return vExtensions;
		}


		//---------------------------------------------------------------------------------------
		// Function name	: GetExtension()
		// Description	    : Returns a particular extension present in this X509CRLEntry depending
		//                    on the object identifier provided. This method iterates over the NSS
		//                    array of extensions, compare each extension's object identifier with 
		//                    the one provided. If the object identifiers match, this method constructs
		//                    a X509Extension object from that extension and returns it. If the
		//                    object identifiers don't match, this method returns smart pointer to NULL.
		// Return type		: auto_ptr<X509Extension>
		//						Smart pointer to extension.
		// Argument         : const string &OID
		//						Object identifier of extension to get.
		//---------------------------------------------------------------------------------------
		auto_ptr<X509Extension> X509CRLEntry::GetExtension(const asn1::ObjectID &OID) const /* throw (Exception) */
		{
			if(!m_pCRLEntry)
				throw NullPointerException("There is no CRLEntry to get extension from.");

			int Pos = ::X509_REVOKED_get_ext_by_OBJ(m_pCRLEntry, OID.m_pObjectID, -1);
			X509_EXTENSION *pExt = X509_REVOKED_get_ext(m_pCRLEntry, Pos);
			if(!pExt)
			{
				return auto_ptr<X509Extension>(NULL);
			}

			switch(::OBJ_obj2nid(OID.m_pObjectID))
			{
			case NID_invalidity_date:
				{
					auto_ptr<X509Extension> pInvalidityDateExt(new extensions::InvalidityDate);
					pInvalidityDateExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pInvalidityDateExt;
				}

			case NID_crl_reason:
				{
					auto_ptr<X509Extension> pReasonCodeExt(new extensions::ReasonCode);
					pReasonCodeExt->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pReasonCodeExt;
				}

			default:
				{
					auto_ptr<X509Extension> pExtension(new X509Extension);
					pExtension->m_pCertExtension = X509_EXTENSION_dup(pExt);
					return pExtension;
				}
			}

		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRLEntry::AddExtension(const X509Extension &ext)
		{
			if(!m_pCRLEntry)
			{
				m_pCRLEntry = X509_REVOKED_new();
				if(!m_pCRLEntry)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}
			}

			int iExtLoc = X509_REVOKED_add_ext(m_pCRLEntry, ext.m_pCertExtension, -1);
			if(iExtLoc == -1)
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
		bool X509CRLEntry::RemoveExtension(const asn1::ObjectID &oid)
		{
			if(!m_pCRLEntry)
				throw NullPointerException("There is no CRLEntry to remove extension from.");

			int Pos = ::X509_REVOKED_get_ext_by_OBJ(m_pCRLEntry, oid.m_pObjectID, -1);
			X509_EXTENSION *pExt = ::X509_REVOKED_delete_ext(m_pCRLEntry, Pos);
			if(NULL == pExt)
				return false;

			::X509_EXTENSION_free(pExt);
			return true;
		}

		//---------------------------------------------------------------------------------------
		// Function name	: 
		// Description	    : 
		// Return type		: 
		// Argument         : 
		//---------------------------------------------------------------------------------------
		void X509CRLEntry::RemoveAllExtensions()
		{
			if(!m_pCRLEntry)
				throw NullPointerException("There is no CRLEntry to remove all extensions from.");

			if(m_pCRLEntry->extensions)
			{
				sk_X509_EXTENSION_pop_free(m_pCRLEntry->extensions, X509_EXTENSION_free);
				m_pCRLEntry->extensions = NULL;
			}
		}
	}
}

