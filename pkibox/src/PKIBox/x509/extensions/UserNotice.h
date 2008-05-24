
#ifndef PKIBOX_X509_EXTENSIONS_USER_NOTICE_H
#define PKIBOX_X509_EXTENSIONS_USER_NOTICE_H

typedef struct USERNOTICE_st USERNOTICE;

#include <memory>
#include <string>

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			class NoticeReference;

			//! This class represents UserNotice in PolicyQualifier.
			/*!
				UserNotice ::= SEQUENCE {
					noticeRef     NoticeReference OPTIONAL,
					explicitText  DisplayText OPTIONAL}

				NoticeReference ::= SEQUENCE {
					organization  DisplayText,
					noticeNumbers SEQUENCE OF INTEGER }

				DisplayText ::= CHOICE {
					visibleString    VisibleString  (SIZE (1..200)),
					bmpString        BMPString      (SIZE (1..200)),
					utf8String       UTF8String     (SIZE (1..200)) }
			*/
			class UserNotice
			{
				friend class PolicyQualifierInfo;

			public:
				//! Default constructor. Constructs an empty UserNotice object.
				UserNotice(void);

				virtual ~UserNotice(void);

				//! Constructs a UserNotice from a NoticeReference.
				/*!
					\param const NoticeReference &NoticeRef: NoticeReference to construct UserNotice from
				*/
				explicit UserNotice(const NoticeReference &NoticeRef);

				//! Constructs a UserNotice from explicit text.
				/*!
					\param const std::string &szExplicitText: Explicit text as string to construct UserNotice
				*/
				explicit UserNotice(const std::string &szExplicitText);

				//! Copy constructor.
				/*!
					\param const UserNotice &rhs
				*/
				UserNotice(const UserNotice &rhs);

				//! Copy assignment operator.
				/*!
					\param const UserNotice &rhs
					\return UserNotice &
				*/
				UserNotice &operator=(const UserNotice &rhs);

				//! Returns NoticeReference value if NoticeReference field is set.
				/*!
					\return std::auto_ptr<NoticeReference>: NoticeReference if present, other wiae null
				*/
				std::auto_ptr<NoticeReference> GetNoticeReference() const;

				//! Returns explicitText value if explicitText field is set. 
				/*!
					\return std::string: ExplicitText if present otherwise empty string
				*/
				std::string GetExplicitText() const;

			private:
				USERNOTICE	*m_pUserNotice;
			};
		}
	}
}

#endif // !PKIBOX_X509_EXTENSIONS_USER_NOTICE_H
