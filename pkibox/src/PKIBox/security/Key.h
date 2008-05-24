
#ifndef PKIBOX_SECURITY_KEY_H
#define PKIBOX_SECURITY_KEY_H

#include <string>

namespace PKIBox
{
	namespace security
	{
		//! The Key interface is the top-level interface for all keys. It defines the functionality shared by all key objects.
		class IKey
		{
		public:
			//! Returns the standard algorithm name for this key. 
			/*!
				\return std::string: the standard name of the algorithm as string
			*/
			virtual std::string GetAlgorithmName() const = 0;
		};
	}
}

#endif // !PKIBOX_SECURITY_KEY_H

