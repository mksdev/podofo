
#ifndef PKIBOX_UTILS_DATE_H
#define PKIBOX_UTILS_DATE_H

#include <ctime>
#include <string>

namespace PKIBox
{
	namespace utils
	{
		// Forward declarations.
		class TimeSpan;

		//! This class represents a date. It can be used for date and time manipulation.
		class DateTime
		{
		public:

			//! Static method for getting current time as Date object.
			/*!
				\return DateTime
			*/
			static DateTime GetSystemCurrentTime();

			//! Default constructor. Initializes underlying integer with zero.
			DateTime();

			//! Constructs a Date object from an time_t.
			/*!
				\param time_t Time
			*/
			explicit DateTime(time_t Time);

			//! Constructs a Date object from C DateTime structure tm. 
			/*!
				\param const tm *ptm
			*/
			explicit DateTime(const tm *ptm);

			//!  Constructs a Date object from individual components.
			/*!
				\param int nYear
				\param int nMonth
				\param int nDay
				\param int nHour
				\param int nMin
				\param int nSec
				\param int nDST = -1
			*/
			DateTime(int nYear, int nMonth, int nDay, int nHour, int nMin, int nSec, int nDST = -1);

			//!  Copy constructor.
			/*!
				\param const DateTime& DateSrc
			*/
			DateTime(const DateTime& DateSrc);

			//!  Copy Assignment operator .
			/*!
				\param const DateTime& DateSrc
				\return DateTime &
			*/
			DateTime &operator=(const DateTime& DateSrc);

			//! Assignment operator for an assignment from time_t.
			/*!
				\param time_t t
				\return DateTime &
			*/
			DateTime &operator=(time_t t);

			//! Breaks down a Date object into components — based on UTC.
			/*!
				\return const tm *
			*/
			const tm *GetGmtTm() const;

			//! Breaks down a Date object into components — based on the local time zone.
			/*!
				\return const tm *
			*/
			const tm *GetLocalTm() const;

			//! Returns a time_t value for the given Date object.
			/*!
				\return time_t 
			*/
			time_t GetTime() const;

			//! Returns year part of this date object.
			/*!
				\return int 
			*/
			int GetYear() const;

			//! Returns month part of this date object.
			/*!
				Month starts from 1. i.e. 1 == Jan
				\return int 
			*/
			int GetMonth() const;       

			//! Returns the day part of this date object.
			/*!
				\return int 
			*/
			int GetDay() const;         

			//! Returns hour part of this date object.
			/*!
				\return int 
			*/
			int GetHour() const;

			//! Returns minute part of this date object.
			/*!
				\return int 
			*/
			int GetMinute() const;

			//! Returns second part of this date object.
			/*!
				\return int 
			*/
			int GetSecond() const;

			//! Returns weekday of this date object.
			/*!
				Weekdays start from 1 i.e. 1=Sun, 2=Mon, ..., 7=Sat.
				\return int
			*/
			int GetDayOfWeek() const;   

			//! Equality operator.
			/*!
				\param DateTime Date
				\return bool
			*/
			bool operator==(DateTime Date) const;

			//! Non-Equality operator.
			/*!
				\param DateTime Date
				\return bool
			*/
			bool operator!=(DateTime Date) const;

			//! Less than operator.
			/*!
				\param DateTime Date
				\return bool
			*/
			bool operator<(DateTime Date) const;

			//! Greater than operator.
			/*!
				\param DateTime Date
				\return bool
			*/
			bool operator>(DateTime Date) const;

			//! Less than or equal to operator.
			bool operator<=(DateTime Date) const;

			//! Greater than or equal to operator.
			/*!
				\param DateTime Date
				\return bool
			*/
			bool operator>=(DateTime Date) const;

			//! Arithmetic operators.
			DateTime &operator-=( TimeSpan Span );
			DateTime &operator+=( TimeSpan Span );
			TimeSpan operator-( DateTime Time ) const;
			DateTime operator-( TimeSpan Span ) const;
			DateTime operator+( TimeSpan Span ) const;

			//! Converts a Date object into a formatted string — based on the local time zone. Same semantics as strftime(). 
			/*!
				\param const char *pFormat
				\return std::string 
			*/
			std::string Format(const char *pFormat) const;

			//! Converts a Date object into a formatted string — based on UTC. Same semantics as strftime(). 
			/*!
				\param const char *pFormat
				\return std::string 
			*/
			std::string FormatGmt(const char *pFormat) const;

		private:
			time_t m_Time;		// Underlying C structure.
		};
	}
}

#endif // PKIBOX_UTILS_DATE_H

