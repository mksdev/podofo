
#ifndef PKIBOX_X509_EXTENSIONS_CRL_DISTRIBUTION_POINT_H
#define PKIBOX_X509_EXTENSIONS_CRL_DISTRIBUTION_POINT_H

typedef struct DIST_POINT_st DIST_POINT;

#include <memory>
#include <vector>

namespace PKIBox
{
	namespace asn1
	{
		class GeneralName;
	}

	namespace x509
	{
		class CX509Certificate;

		namespace extensions
		{
			//! This class represents ASN.1 type DistributionPoint.
			/*!
				The ASN.1 definition of DistributionPoint is 

				DistributionPoint ::= SEQUENCE {<br>
					distributionPoint       [0]     DistributionPointName OPTIONAL,<br>
					reasons                 [1]     ReasonFlags OPTIONAL,<br>
					cRLIssuer               [2]     GeneralNames OPTIONAL }<br>

				DistributionPointName ::= CHOICE {<br>
					fullName                [0]     GeneralNames,<br>
					nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }<br>

				ReasonFlags ::= BIT STRING {<br>
					unused                  (0),<br>
					keyCompromise           (1),<br>
					cACompromise            (2),<br>
					affiliationChanged      (3),<br>
					superseded              (4),<br>
					cessationOfOperation    (5),<br>
					certificateHold         (6),<br>
					privilegeWithdrawn      (7),<br>
					aACompromise            (8) }<br>
			*/
			class CRLDistributionPoint
			{
				friend class x509::CX509Certificate;
				friend class CRLDistributionPoints;

			public:
				//! This enumeration represents the reason flags of a DistributionPoint.
				enum  RevocationReason
				{
					unused  = 0,
					keyCompromise,
					cACompromise,
					affiliationChanged,
					superseded,
					cessationOfOperation,
					certificateHold,
					privilegeWithdrawn,
					aACompromise
				};

				//! Default constructor. Sets m_pCRLDistPoint to NULL.
				CRLDistributionPoint(void);

				virtual ~CRLDistributionPoint(void);

				//! Copy constructor.
				/*!
					\param const CRLDistributionPoint &rhs
				*/
				CRLDistributionPoint(const CRLDistributionPoint &rhs);

				//! Copy assignment operator.
				/*!
					\param const CRLDistributionPoint &rhs
					\return CRLDistributionPoint &
				*/
				CRLDistributionPoint &operator=(const CRLDistributionPoint &rhs);

				//! Returns the distribution point name of this DistributionPoint.
				/*!
					\return std::auto_ptr<asn1::GeneralName>: the name as GeneralName
				*/
				std::auto_ptr<asn1::GeneralName> GetDistributionPointName() const;

				//! Sets the distribution point name of this DistributionPoint.
				/*!
					\param const asn1::GeneralName &DPName: the name as GeneralName
				*/
				void SetDistributionPointName(const asn1::GeneralName &DPName) /* throw (Exception)*/;

				//! Returns CRL issuer specified in this DistributionPoint.
				/*!
					\return std::vector<asn1::GeneralName>: the CRL Issuer as vector of GeneralName object
				*/
				std::vector<asn1::GeneralName> GetCRLIssuer() const;

				//! Sets CRL issuer of this DistributionPoint.
				/*!
					\param const std::vector<asn1::GeneralName> &crlIssuer: the CRL Issuer value to be set as GeneralName
				*/
				void SetCRLIssuer(const std::vector<asn1::GeneralName> &crlIssuer) /* throw (Exception)*/;

				//! Checks whether a specified reason is present in this DistributionPoint.
				/*!
					\param RevocationReason Reason: revocation reason to be checked
					\return bool: true if particular revocation reason set, false otherwise
				*/
				bool IsReason(RevocationReason Reason) const; 

				//! Returns all the reason flags specified in this DistributionPoint.
				/*!
					\return unsigned char: the reason flags specification
				*/
				unsigned char GetReasonFlags() const;

				//! Sets the reason flag for this DistributionPoint.
				/*!
					\param RevocationReason reason: particular revocation reason to be set
				*/
				void SetReasonFlags(RevocationReason reason) /* throw (Exception)*/;

			private:
				DIST_POINT *m_pCRLDistPoint;	// Pointer to underlying DistributionPoint structure.
			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_CRL_DISTRIBUTION_POINT_H
