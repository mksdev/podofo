
#include "UserNotice.h"

// -------------- OpenSSL Includes -----------------------
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "../../openssl/Globals.h"
#include "../../NullPointerException.h"
#include "NoticeReference.h"

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
			UserNotice::UserNotice(void) : m_pUserNotice(NULL)
			{

			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			UserNotice::UserNotice(const NoticeReference &NoticeRef): m_pUserNotice(NULL)
			{
				m_pUserNotice = USERNOTICE_new();
				if(!m_pUserNotice)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pUserNotice->noticeref = NOTICEREF_dup(NoticeRef.m_pNoticeRef);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			UserNotice::UserNotice(const string &szExplicitText): m_pUserNotice(NULL)
			{
				m_pUserNotice = USERNOTICE_new();
				if(!m_pUserNotice)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());
					throw Exception(pc);
				}

				m_pUserNotice->exptext = ASN1_STRING_new();
				int iRet = ASN1_STRING_set(m_pUserNotice->exptext, szExplicitText.data(), szExplicitText.size() );
				if(iRet == -1)
				{
					const char *pc = ::ERR_reason_error_string(::ERR_get_error());

					if(m_pUserNotice)
						USERNOTICE_free(m_pUserNotice);

					throw Exception(pc);
				}
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			UserNotice::~UserNotice(void)
			{
				if(m_pUserNotice)
					USERNOTICE_free(m_pUserNotice);
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			UserNotice::UserNotice(const UserNotice &rhs) : m_pUserNotice(NULL)
			{
				m_pUserNotice = USERNOTICE_dup(rhs.m_pUserNotice);
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			UserNotice &UserNotice::operator=(const UserNotice &rhs)
			{
				// Check for self assignment
				if (this == &rhs) 
					return *this;

				// delete already allocated memory
				if(m_pUserNotice)
				{
					USERNOTICE_free(m_pUserNotice);
				}

				// Assign new values
				m_pUserNotice = USERNOTICE_dup(rhs.m_pUserNotice);
				return *this;
			}

			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			auto_ptr<NoticeReference> UserNotice::GetNoticeReference() const
			{
				if(!m_pUserNotice)
					throw NullPointerException("There is no UserNotice to get NoticeReference from.");


				if(m_pUserNotice->noticeref)
				{
					auto_ptr<NoticeReference> pNoticeRef( new NoticeReference );
					pNoticeRef->m_pNoticeRef = NOTICEREF_dup(m_pUserNotice->noticeref);
					return pNoticeRef;
				}

				return auto_ptr<NoticeReference>(NULL);
			}


			//---------------------------------------------------------------------------------------
			// Function name	: 
			// Description	    : 
			// Return type		: 
			// Argument         : 
			//---------------------------------------------------------------------------------------
			string UserNotice::GetExplicitText() const
			{
				if(!m_pUserNotice)
					throw NullPointerException("There is no UserNotice to get ExplicitText from.");

				if(m_pUserNotice->exptext)
				{
					return string( (char *) m_pUserNotice->exptext->data, m_pUserNotice->exptext->length);
				}

				return "";
			}
		}
	}

}


