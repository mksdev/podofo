/***************************************************************************
 *   Copyright (C) 2008 by Dominik Seichter, Craig Ringer                  *
 *   domseichter@web.de                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Library General Public License as       *
 *   published by the Free Software Foundation; either version 2 of the    *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU Library General Public     *
 *   License along with this program; if not, write to the                 *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include "../PdfDefines.h"
#include "PdfMutex.h"
#include "PdfMutexWrapper.h"

namespace PoDoFo {
namespace Util {

PdfMutex::PdfMutex() { }
PdfMutex::~PdfMutex() { }

//---------------------------------------------------------------------------

#if defined(PODOFO_MULTI_THREAD)
#  if defined(_WIN32)

// begin - from PdfMutexImpl_win32.h

PdfMutexImpl::PdfMutexImpl()
{
    InitializeCriticalSection( &m_cs );
}

PdfMutexImpl::~PdfMutexImpl()
{
    DeleteCriticalSection( &m_cs );
}

void PdfMutexImpl::Lock()
{
    EnterCriticalSection( &m_cs );
}

bool PdfMutexImpl::TryLock()
{
    return (TryEnterCriticalSection( &m_cs ) ? true : false);
}

void PdfMutexImpl::UnLock()
{
    LeaveCriticalSection( &m_cs );
}

// end - from PdfMutexImpl_win32.h

#  else // _WIN32

// begin - from PdfMutexImpl_pthread.h

PdfMutexImpl::PdfMutexImpl() {
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init( &m_mutex, &attr );
}

PdfMutexImpl::~PdfMutexImpl()
{
    pthread_mutex_destroy( &m_mutex );
}

void PdfMutexImpl::Lock()
{
    if( pthread_mutex_lock( &m_mutex ) != 0 ) 
    {
	    PODOFO_RAISE_ERROR( ePdfError_MutexError );
    }
}

bool PdfMutexImpl::TryLock()
{
    int nRet = pthread_mutex_trylock( &m_mutex );
    if( nRet == 0 )
	    return true;
    else if( nRet == EBUSY )
	    return false;
    else
    {
	    PODOFO_RAISE_ERROR( ePdfError_MutexError );
    }
}

void PdfMutexImpl::UnLock()
{
    if( pthread_mutex_unlock( &m_mutex ) != 0 )
    {
	    PODOFO_RAISE_ERROR( ePdfError_MutexError );
    }
}

// end - from PdfMutexImpl_pthread.h

#  endif // _WIN32
#else // PODOFO_MULTI_THREAD

// begin - from PdfMutexImpl_noop.h
PdfMutexImpl::PdfMutexImpl() { }
PdfMutexImpl::~PdfMutexImpl() { }
void PdfMutexImpl::Lock() { }
bool PdfMutexImpl::TryLock() { return true; }
void PdfMutexImpl::UnLock() { }
// end - from PdfMutexImpl_noop.h

#endif // PODOFO_MULTI_THREAD

//---------------------------------------------------------------------------

PdfMutexWrapper::PdfMutexWrapper( PdfMutex & rMutex )
    : m_rMutex( rMutex )
{
    m_rMutex.Lock();
}


PdfMutexWrapper::~PdfMutexWrapper()
{
#if defined(DEBUG)
    try {
	m_rMutex.UnLock();
    }
    catch( const PdfError & rError ) 
    {
	rError.PrintErrorMsg();
        throw rError;
    }
#else
    m_rMutex.UnLock();
#endif
}

}; // namespace Util
}; // namespace PoDoFo
