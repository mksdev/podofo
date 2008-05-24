
#ifndef PKIBOX_UTILS_ARITHMETIC_EXCEPTION_H
#define PKIBOX_UTILS_ARITHMETIC_EXCEPTION_H

#include <string>
#include "../Exception.h"

namespace PKIBox
{
	namespace utils
	{
		//! Thrown when an exceptional arithmetic condition has occurred.
		class ArithmeticException : public Exception
		{
		public:
			//! Constructs an ArithmeticException without an error description.
			ArithmeticException(void);

			//! Construct an ArithmeticException object from an error description.
			/*!
				\param const std::string &sErrMsg: Error message
			*/
			explicit ArithmeticException(const std::string &sErrMsg);

			virtual ~ArithmeticException(void);
		};
	}
}

#endif // !PKIBOX_UTILS_ARITHMETIC_EXCEPTION_H

