
#ifndef PKIBOX_UTILS_TIME_SPAN_H
#define PKIBOX_UTILS_TIME_SPAN_H

#include <ctime>
#include <string>

namespace PKIBox
{
	namespace utils
	{
		//! This class represents an amount of time.
		class TimeSpan
		{
		public:
			//! Default constructor. Initializes to zero.
			TimeSpan();

			//! Constructs a TimeSpan from time_t.
			/*!
				\param time_t time
			*/
			TimeSpan( time_t time );

			//! Constructs a TimeSpan from components.
			/*!
				\param long lDays
				\param int nHours
				\param int nMins
				\param int nSecs
			*/
			TimeSpan( long lDays, int nHours, int nMins, int nSecs );

			//! Returns number of days in this TimeSpan.
			/*!
				\return long: Number of days in timespan
			*/
			long GetDays() const;

			//! Returns total number of complete hours in this TimeSpan.
			/*!
				\return long: number of hours in timespan
			*/
			long GetTotalHours() const ;

			//! Returns number of hours in this TimeSpan.
			/*!
				\return long: number of hours in timespan
			*/
			long GetHours() const ;

			//! Returns total number of complete minutes in this TimeSpan.
			/*!
				\return long: total minutes in timespan
			*/
			long GetTotalMinutes() const ;

			//! Returns number of minutes in this TimeSpan.
			/*!
				\return long: minutes in timespan
			*/
            long GetMinutes() const ;

			//! Returns total number of complete seconds in this TimeSpan.
			/*!
				\return long: total seconds in timespan
			*/
			long GetTotalSeconds() const ;

			//! Returns total number of seconds in this TimeSpan.
			/*!
				\return long: second in timespan
			*/
			long GetSeconds() const ;

			//! Returns value of this TimeSpan object.
			/*!
				\return time_t: timespan in time_t fromat
			*/
			time_t GetTimeSpan() const ;

			//! Converts this TimeSpan into a formatted string.
			/*! 
				the only valid formats:
			      %D - # of days
			      %H - hour in 24 hour format
			      %M - minute (0-59)
			      %S - seconds (0-59)
			      %% - percent sign
				\param const char *pFormat: required format of timespan
				\return std::string: string representing the timespan of desired fromat
			*/
			std::string Format(const char *pFormat) const;

			//! Arithmetic operators.
			/*!
				\param const TimeSpan rhs
				\return TimeSpan 
			*/
			TimeSpan operator+( const TimeSpan rhs ) const;

			//! Arithmetic operators.
			/*!
				\param const TimeSpan rhs
				\return TimeSpan 
			*/
			TimeSpan operator-( const TimeSpan rhs ) const;

			//! Arithmetic operators.
			/*!
				\param const TimeSpan rhs
				\return TimeSpan 
			*/
			TimeSpan& operator+=( const TimeSpan rhs ) ;

			//! Arithmetic operators.
			/*!
				\param const TimeSpan rhs
				\return TimeSpan 
			*/
			TimeSpan& operator-=( const TimeSpan rhs ) ;

			//! Relational operators.
			/*!
				\param const TimeSpan rhs
				\return bool 
			*/
			bool operator==( const TimeSpan rhs ) const ;

			//! Relational operators.
			/*!
				\param const TimeSpan rhs
				\return bool 
			*/
			bool operator!=( const TimeSpan rhs ) const ;

			//! Relational operators.
			/*!
				\param const TimeSpan rhs
				\return bool 
			*/
			bool operator<( const TimeSpan rhs ) const ;

			//! Relational operators.
			/*!
				\param const TimeSpan rhs
				\return bool 
			*/
			bool operator>( const TimeSpan rhs ) const ;

			//! Relational operators.
			/*!
				\param const TimeSpan rhs
				\return bool 
			*/
			bool operator<=( const TimeSpan rhs ) const ;

			//! Relational operators.
			/*!
				\param const TimeSpan rhs
				\return bool 
			*/
			bool operator>=( const TimeSpan rhs ) const ;

		private:
			time_t m_TimeSpan;
		};
	}
}


#endif //!PKIBOX_UTILS_TIME_SPAN_H

