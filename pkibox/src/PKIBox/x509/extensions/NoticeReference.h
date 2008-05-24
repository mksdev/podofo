
#ifndef PKIBOX_X509_EXTENSIONS_NOTICE_REFERENCE_H
#define PKIBOX_X509_EXTENSIONS_NOTICE_REFERENCE_H

typedef struct NOTICEREF_st NOTICEREF;

#include <vector>
#include <string>

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			//! This class represents NoticeReference in UserNotice.
			/*!
				NoticeReference ::= SEQUENCE {
					organization  DisplayText,
					noticeNumbers SEQUENCE OF INTEGER }
			*/
			class NoticeReference
			{
				friend class UserNotice;

			public:
				//! Default constructor. Constructs an empty NoticeReference object.
				NoticeReference(void);

				virtual ~NoticeReference(void);

				//! Constructs a NoticeReference from organization and notice numbers.
				/*!
					\param const std::string &szOrganization
					\param const std::vector<int> &vNoticeNumbers
				*/
				NoticeReference(const std::string &szOrganization, const std::vector<int> &vNoticeNumbers);

				//! Copy constructor.
				/*!
					\param const NoticeReference &rhs
				*/
				NoticeReference(const NoticeReference &rhs);

				//! Copy assignment operator.
				/*!
					\param const NoticeReference &rhs
					\return NoticeReference &
				*/
				NoticeReference &operator=(const NoticeReference &rhs);

				//! Returns organization value if this PolicyQualifierInfo is a User Notice Qualifier and the organization field is set. 
				/*!
					\return std::string: organization name as string
				*/
				std::string GetOrganization() const;

				//! Returns notice numbers if this PolicyQualifierInfo is a User Notice Qualifier and notice numbers are set. 
				/*!
					\return std::vector<int>
				*/
				std::vector<int> GetNoticeNumbers() const;

			private:
				NOTICEREF	*m_pNoticeRef;
			};
		}
	}
}


#endif // !PKIBOX_X509_EXTENSIONS_NOTICE_REFERENCE_H

