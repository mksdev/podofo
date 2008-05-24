
#ifndef PKIBOX_X509_EXTENSIONS_POLICY_QUALIFIER_INFO_H
#define PKIBOX_X509_EXTENSIONS_POLICY_QUALIFIER_INFO_H

typedef struct POLICYQUALINFO_st POLICYQUALINFO;

#include <memory>
#include <string>

namespace PKIBox
{
	namespace asn1
	{
		class ObjectID;
	}

	namespace x509
	{
		namespace extensions
		{
			class UserNotice;

			//! This class represents the PolicyQualifierInfo in PolicyInformation.
			/*!
				PolicyQualifierInfo ::= SEQUENCE {
					policyQualifierId   PolicyQualifierId,
					qualifier           ANY DEFINED BY policyQualifierId }

				Qualifier ::= CHOICE {
					cPSuri         CPSuri,     -- CPS Pointer qualifier
					userNotice     UserNotice  -- User Notice qualifier	}

				CPSuri ::= IA5String
			*/
			class PolicyQualifierInfo
			{
				friend class PolicyInformation;

			public:
				//! Default constructor. Creates an empty PolicyQualifierInfo object.
				PolicyQualifierInfo(void);

				virtual ~PolicyQualifierInfo(void);

				//! Creates a new PolicyQualifierInfo from a CPS Pointer qualifier.  
				/*!
					\param const std::string &CpsUri: the pointer as URI
				*/
				explicit PolicyQualifierInfo(const std::string &CpsUri);

				//! Creates a new PolicyQualifierInfo from a User Notice.  
				/*!
					\param const UserNotice &UserNotice: userNotice create policy qualifier from
				*/
				explicit PolicyQualifierInfo(const UserNotice &UserNotice);

				//! Copy Constructor
				/*!
					\param const PolicyQualifierInfo &PQInfo
				*/
				PolicyQualifierInfo(const PolicyQualifierInfo &PQInfo);

				//! Copy assignment operator.
				/*!
					\param const PolicyQualifierInfo &rhs
					\return PolicyQualifierInfo &
				*/
				PolicyQualifierInfo &operator=(const PolicyQualifierInfo &rhs);

				//! Returns policy qualifier id.
				/*!
					\return asn1::ObjectID: the PolicyQualifierID
				*/
				asn1::ObjectID GetPolicyQualifierID() const;

				//! Gets the CPSUri or empty string if this PolicyQualifierInfo is not a CPS Pointer. 
				/*!
					\return std::string: the CPSUri if this PolicyQualifierInfo is a CPS Pointer
				*/
				std::string GetCPSuri() const;

				//! Returns UserNotice contained in this PolicyInformation.
				/*!
					\return std::auto_ptr<UserNotice>: the UserNotice if this PolicyQualifierInfo is a USERNOTICE Pointer
				*/
				std::auto_ptr<UserNotice> GetUserNotice() const;

			private:
				POLICYQUALINFO *m_pPolicyQualifierInfo;
			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_POLICY_QUALIFIER_INFO_H

