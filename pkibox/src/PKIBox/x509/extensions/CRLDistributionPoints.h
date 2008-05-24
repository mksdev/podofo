
#ifndef PKIBOX_X509_EXTENSIONS_CRL_DISTRIBUTION_POINTS_H
#define PKIBOX_X509_EXTENSIONS_CRL_DISTRIBUTION_POINTS_H

#include <memory>
#include <vector>
#include "../X509Extension.h"

namespace PKIBox
{
	namespace x509
	{
		namespace extensions
		{
			class CRLDistributionPoint;

			//! This class represents the extension CRLDistributionPoints.
			/*! 
				The ASN.1 definition of CRLDistributionPoints is

				cRLDistributionPoints ::= {<br>
					CRLDistPointsSyntax }<br>

				CRLDistPointsSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint<br>

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
					certificateHold         (6) }<br>
			*/
			class CRLDistributionPoints : public x509::X509Extension
			{
			public:
				//! Default constructor. Creates an empty CRLDistributionPoints.
				CRLDistributionPoints(void);

				virtual ~CRLDistributionPoints(void);

				//! Returns the nth CDP in the extension.
				/*!
					\param unsigned int n: position of CDP to get
					\return std::auto_ptr<CRLDistributionPoint>: CRL distribution point at nth position
				*/
				std::auto_ptr<CRLDistributionPoint> GetCDP(unsigned int n) const;

				//! Returns the number of CDPs in the extension.
				/*!
					\return unsigned int: number of CDPs present
				*/
				unsigned int GetNumberOfCDPs() const;

				//! Returns a collection of all the CDPs contained in the extension.
				/*!
					\return std::vector<CRLDistributionPoint>: vector of distribution points
				*/
				std::vector<CRLDistributionPoint> GetCDPs() const;

				//! Inserts the CDP in the extension.
				/*!
					\param const CRLDistributionPoint &CDP: the CRL distribution point to add
				*/
				void AddCDP(const CRLDistributionPoint &CDP) /* throw (Exception)*/;
			};
		}
	}

}

#endif // !PKIBOX_X509_EXTENSIONS_CRL_DISTRIBUTION_POINTS_H
