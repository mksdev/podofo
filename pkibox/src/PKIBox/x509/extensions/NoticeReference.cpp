
#include "NoticeReference.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../Exception.h"
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
			NoticeReference::NoticeReference(void) : m_pNoticeRef(NULL)
			{
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			NoticeReference::~NoticeReference(void)
			{
				if(m_pNoticeRef)
					NOTICEREF_free(m_pNoticeRef);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			NoticeReference::NoticeReference(const NoticeReference &rhs) : m_pNoticeRef(NULL)
			{
				m_pNoticeRef = NOTICEREF_dup(rhs.m_pNoticeRef);
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			NoticeReference &NoticeReference::operator=(const NoticeReference &rhs)
			{
				// Check for self assignment
				if (this == &rhs) 
					return *this;

				// delete already allocated memory
				if(m_pNoticeRef)
					NOTICEREF_free(m_pNoticeRef);

				// Assign new values
				m_pNoticeRef = NOTICEREF_dup(rhs.m_pNoticeRef);
				return *this;
			}

			//---------------------------------------------------------------------------------------
			// Function name	: CPolicyQualifierInfo
			// Description	    : Creates a new PolicyQualifierInfo from a user notice qualifier specified by reference information and/or an explicit text.  
			// Return type		: 
			// Argument         : const CObjectID &organization, vector<int> noticeNumbers, const CObjectID &explicitText
			//---------------------------------------------------------------------------------------
			NoticeReference::NoticeReference(const string &szOrganization, const vector<int> &vNoticeNumbers) : m_pNoticeRef(NULL)
			{
				m_pNoticeRef = NOTICEREF_new();
				if(!m_pNoticeRef)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pNoticeRef->organization = ASN1_STRING_new();
				int iRet = ASN1_STRING_set( m_pNoticeRef->organization, szOrganization.data(), szOrganization.size() );

				for(unsigned int i=0; i<vNoticeNumbers.size(); ++i)
				{
					ASN1_INTEGER *pNoticeNumber = ASN1_INTEGER_new();
					ASN1_INTEGER_set(pNoticeNumber, vNoticeNumbers[i]);
					sk_ASN1_INTEGER_push(m_pNoticeRef->noticenos, pNoticeNumber);
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetNoticeNumbers
			// Description	    : Gets the notice numbers if this PolicyQualifierInfo is a User Notice Qualifier and notice numbers are set. 
			// Return type		: vector<int>
			// Argument         : void
			//---------------------------------------------------------------------------------------
			vector<int> NoticeReference::GetNoticeNumbers() const
			{
				if(!m_pNoticeRef)
				{
					throw Exception("There isn't any NoticeReference to get Notice Numbers from.");
				}

				vector<int> vNoticeNumbers;
				int nNoticeCount = sk_ASN1_INTEGER_num( m_pNoticeRef->noticenos );
				for( int iCount=0 ; iCount<nNoticeCount ; iCount++ )
				{
					int iNoticeNumber = ASN1_INTEGER_get( (ASN1_INTEGER *) sk_ASN1_INTEGER_value( m_pNoticeRef->noticenos, iCount) );
					vNoticeNumbers.push_back( iNoticeNumber );
				}

				return vNoticeNumbers;
			}


			//---------------------------------------------------------------------------------------
			// Function name	: GetOrganization
			// Description	    : Gets the organization value if this PolicyQualifierInfo is a User Notice Qualifier and the organization field is set. 
			// Return type		: CObjectID 
			// Argument         : void
			//---------------------------------------------------------------------------------------
			string NoticeReference::GetOrganization() const
			{
				if(!m_pNoticeRef)
				{
					throw Exception("There isn't any NoticeReference to get Organization from.");
				}

				return string( (char *)m_pNoticeRef->organization->data, m_pNoticeRef->organization->length);
			}
		}
	}
}

